import "pe"
rule aPack_v0_82 {
  strings:
    $a0 = { 1E 06 8C CB BA ?? ?? 03 DA 8D ?? ?? ?? FC 33 F6 33 FF 48 4B 8E C0 8E DB }

  condition:
    $a0 at pe.entry_point
}