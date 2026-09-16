rule PEiD_01713_PKLITE_v1_20_ {
  meta:
    description = "[PKLITE v1.20]"
    ep_only     = "true"

  strings:
    $a = { B8 ?? ?? BA ?? ?? 05 ?? ?? 3B 06 ?? ?? 72 ?? B4 09 BA ?? ?? CD 21 B4 4C CD 21 }

  condition:
    $a
}