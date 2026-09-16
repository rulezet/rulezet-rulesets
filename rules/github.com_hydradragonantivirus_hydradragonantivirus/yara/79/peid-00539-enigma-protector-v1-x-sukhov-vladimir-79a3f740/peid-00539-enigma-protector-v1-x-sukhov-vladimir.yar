rule PEiD_00539_ENIGMA_Protector_V1_X____Sukhov_Vladimir_ {
  meta:
    description = "[ENIGMA Protector V1.X -> Sukhov Vladimir]"
    ep_only     = "false"

  strings:
    $a = "Enigma protector v1"

  condition:
    $a
}