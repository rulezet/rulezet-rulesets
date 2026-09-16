import "pe"
rule _Stony_Brook_Pascal_v614_ {
  meta:
    description = "Stony Brook Pascal v6.14"

  strings:
    $0 = { 31 ED 9A ?? ?? ?? ?? 55 89 E5 ?? EC ?? ?? 9A }

  condition:
    $0 at pe.entry_point
}