rule PEiD_02457_UPX_HiT_0_0_1____sibaway7_yahoo_com_ {
  meta:
    description = "[UPX$HiT 0.0.1 -> sibaway7@yahoo.com]"
    ep_only     = "false"

  strings:
    $a = { E2 FA 94 FF E0 61 00 00 00 00 00 00 00 }

  condition:
    $a
}