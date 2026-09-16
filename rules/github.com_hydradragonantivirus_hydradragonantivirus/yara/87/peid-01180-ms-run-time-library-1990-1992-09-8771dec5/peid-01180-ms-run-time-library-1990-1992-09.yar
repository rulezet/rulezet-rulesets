rule PEiD_01180_MS_Run_Time_Library_1990__1992__09__ {
  meta:
    description = "[MS Run-Time Library 1990, 1992 (09)]"
    ep_only     = "true"

  strings:
    $a = { B4 30 CD 21 3C 02 73 ?? C3 8C DF 8B 36 ?? ?? 2E }

  condition:
    $a
}