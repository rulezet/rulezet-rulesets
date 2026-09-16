rule PEiD_00660_EXEStealth_2_75____WebtoolMaster_ {
  meta:
    description = "[EXEStealth 2.75 -> WebtoolMaster]"
    ep_only     = "true"

  strings:
    $a = { 90 60 90 E8 00 00 00 00 5D 81 ED D1 27 40 00 B9 15 00 00 00 }

  condition:
    $a
}