rule PEiD_01852_PseudoSigner_0_1__XCR_0_11_____Anorganix_ {
  meta:
    description = "[PseudoSigner 0.1 [XCR 0.11] -> Anorganix]"
    ep_only     = "true"

  strings:
    $a = { 60 8B F0 33 DB 83 C3 01 83 C0 01 E9 }

  condition:
    $a
}