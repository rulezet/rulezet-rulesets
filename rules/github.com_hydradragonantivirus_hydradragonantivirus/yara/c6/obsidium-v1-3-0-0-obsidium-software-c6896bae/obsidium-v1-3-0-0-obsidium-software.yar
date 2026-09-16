import "pe"
rule Obsidium_V1_3_0_0____Obsidium_Software {
  strings:
    $a0 = { EB 04 ?? ?? ?? ?? E8 ?? 00 00 00 }

  condition:
    $a0 at pe.entry_point
}