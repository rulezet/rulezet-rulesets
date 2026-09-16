import "pe"
rule _eXPressor_V13__CGSoftLabs_ {
  meta:
    description = "eXPressor V1.3 -> CGSoftLabs"

  strings:
    $0 = { 55 8B EC 83 EC ?? 53 56 57 EB 0C 45 }

  condition:
    $0 at pe.entry_point
}