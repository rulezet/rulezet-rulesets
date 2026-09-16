import "pe"
rule Aluwain_v8_09 {
  strings:
    $a0 = { 8B EC 1E E8 ?? ?? 9D 5E }

  condition:
    $a0 at pe.entry_point
}