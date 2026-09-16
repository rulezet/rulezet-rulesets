rule PEiD_02506_VMProtect_0_7x___0_8____PolyTech_ {
  meta:
    description = "[VMProtect 0.7x - 0.8 -> PolyTech]"
    ep_only     = "false"

  strings:
    $a = "[ VMProtect v 0.8 (C) PolyTech ]"

  condition:
    $a
}