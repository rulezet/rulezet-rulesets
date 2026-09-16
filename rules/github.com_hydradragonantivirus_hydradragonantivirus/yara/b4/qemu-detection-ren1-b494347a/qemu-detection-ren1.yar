rule Qemu_Detection_ren1: AntiVM {
  meta:
    description = "Looks for Qemu presence"

  strings:
    $a0 = "qemu" nocase wide ascii

  condition:
    any of them
}