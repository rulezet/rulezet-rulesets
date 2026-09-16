rule PEiD_01815_PseudoSigner_0_1__LCC_Win32_1_x_____Anorganix_ {
  meta:
    description = "[PseudoSigner 0.1 [LCC Win32 1.x] -> Anorganix]"
    ep_only     = "true"

  strings:
    $a = { 64 A1 01 00 00 00 55 89 E5 6A FF 68 ?? ?? ?? ?? 68 9A 10 40 90 50 E9 }

  condition:
    $a
}