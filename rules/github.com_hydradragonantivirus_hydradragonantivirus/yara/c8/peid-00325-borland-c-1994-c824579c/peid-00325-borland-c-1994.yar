rule PEiD_00325_Borland_C___1994_ {
  meta:
    description = "[Borland C++ 1994]"
    ep_only     = "true"

  strings:
    $a = { 8C CA 2E 89 ?? ?? ?? B4 30 CD 21 8B 2E ?? ?? 8B 1E ?? ?? 8E DA A3 ?? ?? 8C }

  condition:
    $a
}