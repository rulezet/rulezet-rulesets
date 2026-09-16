rule PEiD_01028_MEW_5_1_0____Northfox_ {
  meta:
    description = "[MEW 5 1.0 -> Northfox]"
    ep_only     = "true"

  strings:
    $a = { BE 5B 00 40 00 AD 91 AD 93 53 AD 96 56 5F AC C0 C0 }

  condition:
    $a
}