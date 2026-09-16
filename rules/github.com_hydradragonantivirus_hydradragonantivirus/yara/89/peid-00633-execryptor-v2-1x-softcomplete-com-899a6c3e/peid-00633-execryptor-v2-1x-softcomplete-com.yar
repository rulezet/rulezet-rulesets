rule PEiD_00633_EXECryptor_V2_1X____softcomplete_com_ {
  meta:
    description = "[EXECryptor V2.1X -> softcomplete.com]"
    ep_only     = "false"

  strings:
    $a = { 83 C6 14 8B 55 FC E9 ?? FF FF FF }

  condition:
    $a
}