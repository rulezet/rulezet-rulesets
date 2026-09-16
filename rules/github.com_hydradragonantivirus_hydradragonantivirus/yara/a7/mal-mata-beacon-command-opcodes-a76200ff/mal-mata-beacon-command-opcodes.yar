rule MAL_MATA_Beacon_Command_Opcodes {
  meta:
    author      = "Greg Lesnewich"
    date        = "2023-01-18"
    version     = "1.0"
    description = "check for Mata framework beacon opcodes and handshake check"

  strings:
    $CMataNet_Auth = {
      c7 45 c4 00 00 02 00        48 8d 75 c4                 4c 89 f7                    ba 04 00 00 00              b9 01 00 00 00              e8 ?? ?? ?? ??              85 c0                       74 ??                       c7 45 c4 00 00 00 00        48 8d 75 c4                 4c 89 f7                    ba 04 00 00 00              b9 01 00 00 00              41 b8 2c 01 00 00           e8 ?? ?? ?? ??              45 31 e4                    85 c0                       74 ??                       81 7d c4 00 01 02 00        75 ??                       c7 45 c4 00 02 02 00      }

  condition:
    (uint32be(0x0) == 0xCAFEBABE or uint32be(0x0) == 0xCFFAEDFE or uint32be(0x0) == 0xCEFAEDFE) and
    all of them
}