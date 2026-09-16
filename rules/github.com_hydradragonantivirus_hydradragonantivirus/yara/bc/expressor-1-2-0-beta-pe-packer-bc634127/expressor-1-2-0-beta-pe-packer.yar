import "pe"
rule eXPressor_1_2_0_Beta_PE_Packer {
  strings:
    $a0 = { 55 8B EC 81 EC ?? ?? ?? ?? 53 56 57 EB ?? 45 78 50 72 2D 76 2E 31 2E 32 2E 2E }

  condition:
    $a0 at pe.entry_point
}