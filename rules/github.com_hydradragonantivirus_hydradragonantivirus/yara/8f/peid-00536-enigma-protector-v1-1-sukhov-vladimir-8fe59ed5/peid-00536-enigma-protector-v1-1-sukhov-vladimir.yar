rule PEiD_00536_ENIGMA_Protector_V1_1____Sukhov_Vladimir_ {
  meta:
    description = "[ENIGMA Protector V1.1 -> Sukhov Vladimir]"
    ep_only     = "true"

  strings:
    $a = { 60 E8 00 00 00 00 5D 83 ?? ?? 81 }

  condition:
    $a
}