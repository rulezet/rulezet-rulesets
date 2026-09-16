rule PEiD_01841_PseudoSigner_0_1__PENinja_1_31_____Anorganix_ {
  meta:
    description = "[PseudoSigner 0.1 [PENinja 1.31] -> Anorganix]"
    ep_only     = "true"

  strings:
    $a = { 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 E9 }

  condition:
    $a
}