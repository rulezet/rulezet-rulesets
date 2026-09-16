rule PEiD_00634_EXECryptor_V2_1X____SoftComplete_com_ {
  meta:
    description = "[EXECryptor V2.1X -> SoftComplete.com]"
    ep_only     = "true"

  strings:
    $a = { E9 ?? ?? ?? ?? 66 9C 60 50 8D 88 ?? ?? ?? ?? 8D 90 04 16 ?? ?? 8B DC 8B E1 }

  condition:
    $a
}