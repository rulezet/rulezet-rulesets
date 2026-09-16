import "pe"
rule ILUCRYPT_v4_015_rule__exe_ {
  strings:
    $a0 = { 8B EC FA C7 46 F7 ?? ?? 42 81 FA ?? ?? 75 F9 FF 66 F7 }

  condition:
    $a0 at pe.entry_point
}