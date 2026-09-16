rule PEiD_01363_Nullsoft_PIMP_Install_System_v1_3x_ {
  meta:
    description = "[Nullsoft PIMP Install System v1.3x]"
    ep_only     = "true"

  strings:
    $a = { 55 8B EC 81 EC ?? ?? 00 00 56 57 6A ?? BE ?? ?? ?? ?? 59 8D BD }

  condition:
    $a
}