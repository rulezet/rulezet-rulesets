rule PEiD_03510_xPEP_0_3x____xIkUg_ {
  meta:
    description = "[xPEP 0.3x -> xIkUg]"
    ep_only     = "true"

  strings:
    $a = { 55 53 56 51 52 57 E8 16 00 00 00 }

  condition:
    $a
}