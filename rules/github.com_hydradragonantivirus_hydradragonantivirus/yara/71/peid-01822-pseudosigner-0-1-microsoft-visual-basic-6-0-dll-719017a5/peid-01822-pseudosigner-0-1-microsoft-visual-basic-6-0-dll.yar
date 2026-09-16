rule PEiD_01822_PseudoSigner_0_1__Microsoft_Visual_Basic_6_0_DLL__ {
  meta:
    description = "[PseudoSigner 0.1 [Microsoft Visual Basic 6.0 DLL]]"
    ep_only     = "true"

  strings:
    $a = { 90 90 90 90 68 ?? ?? ?? ?? 67 64 FF 36 00 00 67 64 89 26 00 00 F1 90 90 90 90 5A 68 90 90 90 90 68 90 90 90 90 52 E9 90 90 FF }

  condition:
    $a
}