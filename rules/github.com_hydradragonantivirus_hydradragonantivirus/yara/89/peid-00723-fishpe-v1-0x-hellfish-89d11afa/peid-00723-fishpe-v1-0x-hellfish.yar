rule PEiD_00723_FishPE_V1_0X____hellfish_ {
  meta:
    description = "[FishPE V1.0X -> hellfish]"
    ep_only     = "true"

  strings:
    $a = { 60 E8 ?? ?? ?? ?? C3 90 09 00 00 00 2C 00 00 00 ?? ?? ?? ?? C4 03 00 00 BC A0 00 00 00 40 01 00 ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 99 00 00 00 00 8A 00 00 00 10 00 00 ?? ?? 00 00 ?? ?? ?? ?? 00 00 02 00 00 00 A0 00 00 18 01 00 00 }

  condition:
    $a
}