rule PEiD_02154_STNPEE_1_13_ {
  meta:
    description = "[STNPEE 1.13]"
    ep_only     = "true"

  strings:
    $a = { 55 57 56 52 51 53 E8 00 00 00 00 5D 8B D5 81 ED 97 3B 40 00 }

  condition:
    $a
}