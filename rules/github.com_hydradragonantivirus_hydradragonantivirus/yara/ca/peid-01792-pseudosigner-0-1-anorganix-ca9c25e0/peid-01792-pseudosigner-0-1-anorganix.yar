rule PEiD_01792_PseudoSigner_0_1____Anorganix_ {
  meta:
    description = "[PseudoSigner 0.1 -> Anorganix]"
    ep_only     = "true"

  strings:
    $a = { 90 90 90 90 68 ?? ?? ?? ?? 67 64 FF 36 00 00 67 64 89 26 00 00 F1 90 90 90 90 }

  condition:
    $a
}