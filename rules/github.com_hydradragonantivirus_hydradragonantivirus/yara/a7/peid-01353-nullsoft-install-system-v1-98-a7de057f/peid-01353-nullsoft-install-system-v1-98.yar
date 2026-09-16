rule PEiD_01353_Nullsoft_Install_System_v1_98_ {
  meta:
    description = "[Nullsoft Install System v1.98]"
    ep_only     = "true"

  strings:
    $a = { 83 EC 0C 53 56 57 FF 15 2C 81 40 }

  condition:
    $a
}