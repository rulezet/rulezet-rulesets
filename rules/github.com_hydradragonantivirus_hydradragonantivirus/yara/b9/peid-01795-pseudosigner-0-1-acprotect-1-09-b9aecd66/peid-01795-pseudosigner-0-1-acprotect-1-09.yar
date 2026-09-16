rule PEiD_01795_PseudoSigner_0_1__ACProtect_1_09__ {
  meta:
    description = "[PseudoSigner 0.1 [ACProtect 1.09]]"
    ep_only     = "true"

  strings:
    $a = { 60 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 EB 02 00 00 90 90 90 04 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 }

  condition:
    $a
}