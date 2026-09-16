rule PEiD_00528_EncryptPE_V2_2006_1_15____WFS_ {
  meta:
    description = "[EncryptPE V2.2006.1.15 -> WFS]"
    ep_only     = "false"

  strings:
    $a = "EPE: EncryptPE V2.2006.1.15"

  condition:
    $a
}