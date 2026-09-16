rule PEiD_00332_Borland_C___for_Win32_1999_ {
  meta:
    description = "[Borland C++ for Win32 1999]"
    ep_only     = "false"

  strings:
    $a = { EB 10 66 62 3A 43 2B 2B 48 4F 4F 4B 90 }

  condition:
    $a
}