rule PEiD_00537_ENIGMA_Protector_V1_1_CracKed_By__shoooo___fly____Sukhov_Vladimir_ {
  meta:
    description = "[ENIGMA Protector V1.1 CracKed By: shoooo & fly -> Sukhov Vladimir]"
    ep_only     = "true"

  strings:
    $a = { 60 E8 00 00 00 00 5D 83 C5 FA 81 }

  condition:
    $a
}