rule PEiD_01856_PseudoSigner_0_2__32Lite_0_03_____Anorganix_ {
  meta:
    description = "[PseudoSigner 0.2 [32Lite 0.03] -> Anorganix]"
    ep_only     = "true"

  strings:
    $a = { 60 06 FC 1E 07 BE 90 90 90 90 6A 04 68 90 10 90 90 68 }

  condition:
    $a
}