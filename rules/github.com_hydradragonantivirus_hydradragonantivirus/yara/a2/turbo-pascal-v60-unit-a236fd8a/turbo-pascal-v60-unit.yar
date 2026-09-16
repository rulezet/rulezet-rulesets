import "pe"
rule _Turbo_Pascal_v60_Unit_ {
  meta:
    description = "Turbo Pascal v6.0 Unit"

  strings:
    $0 = { 54 50 55 39 00 }

  condition:
    $0 at pe.entry_point
}