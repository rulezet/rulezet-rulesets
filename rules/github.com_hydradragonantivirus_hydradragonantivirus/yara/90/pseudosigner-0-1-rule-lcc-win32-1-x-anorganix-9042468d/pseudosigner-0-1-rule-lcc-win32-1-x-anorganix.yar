import "pe"
rule __PseudoSigner_0_1_rule__LCC_Win32_1_x______Anorganix {
  strings:
    $a0 = { 64 A1 01 00 00 00 55 89 E5 6A FF 68 ?? ?? ?? ?? 68 9A 10 40 90 50 E9 }

  condition:
    $a0 at pe.entry_point
}