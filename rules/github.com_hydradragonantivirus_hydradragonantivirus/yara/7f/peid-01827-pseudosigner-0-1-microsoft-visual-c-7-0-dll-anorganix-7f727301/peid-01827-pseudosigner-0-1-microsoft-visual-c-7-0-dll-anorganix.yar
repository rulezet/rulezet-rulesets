rule PEiD_01827_PseudoSigner_0_1__Microsoft_Visual_C___7_0_DLL_____Anorganix_ {
  meta:
    description = "[PseudoSigner 0.1 [Microsoft Visual C++ 7.0 DLL] -> Anorganix]"
    ep_only     = "true"

  strings:
    $a = { 55 8D 6C 01 00 81 EC 00 00 00 00 8B 45 90 83 F8 01 56 0F 84 00 00 00 00 85 C0 0F 84 ?? ?? ?? ?? E9 }

  condition:
    $a
}