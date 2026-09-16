rule SUSP_LNK_Embedded_ISO_FileHeader {
  meta:
    author      = "Greg Lesnewich"
    description = "look for LNK files that for some reason embed an ISO file based on LNK header and ISO header being valid"
    description = "ISO header rule borrowed from Lars https://github.com/100DaysofYARA/2024/blob/33cad5be966c9d959e8d38bd7669562f11a7b2a2/larsborn/Day_014.yara#L12"
    date        = "2024-02-08"
    version     = "1.0"
    DaysOfYara  = "38/100"

  condition:
    uint32be(0x0) == 0x4c000000 and
    uint32be(0x8001) == 0x43443030 and
    uint32be(0x8002) == 0x44303031  }