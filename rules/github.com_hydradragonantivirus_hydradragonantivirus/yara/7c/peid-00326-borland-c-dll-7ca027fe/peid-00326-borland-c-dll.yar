rule PEiD_00326_Borland_C___DLL_ {
  meta:
    description = "[Borland C++ DLL]"
    ep_only     = "false"

  strings:
    $a = { EB 10 66 62 3A 43 2B 2B 48 4F 4F 4B 90 E9 }

  condition:
    $a
}