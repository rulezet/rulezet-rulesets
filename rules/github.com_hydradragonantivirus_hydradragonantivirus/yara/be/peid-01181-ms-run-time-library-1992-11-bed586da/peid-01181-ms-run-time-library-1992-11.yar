rule PEiD_01181_MS_Run_Time_Library_1992__11__ {
  meta:
    description = "[MS Run-Time Library 1992 (11)]"
    ep_only     = "true"

  strings:
    $a = { B4 51 CD 21 8E DB B8 ?? ?? 83 E8 ?? 8E C0 33 F6 33 FF B9 ?? ?? FC F3 A5 }

  condition:
    $a
}