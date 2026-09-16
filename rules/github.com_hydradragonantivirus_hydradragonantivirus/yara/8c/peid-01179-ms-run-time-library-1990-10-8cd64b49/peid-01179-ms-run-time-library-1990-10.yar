rule PEiD_01179_MS_Run_Time_Library_1990__10__ {
  meta:
    description = "[MS Run-Time Library 1990 (10)]"
    ep_only     = "true"

  strings:
    $a = { E8 ?? ?? 2E FF 2E ?? ?? BB ?? ?? E8 ?? ?? CB }

  condition:
    $a
}