rule PEiD_03402_Vx__Kuku_886_ {
  meta:
    description = "[Vx: Kuku.886]"
    ep_only     = "true"

  strings:
    $a = { 06 1E 50 8C C8 8E D8 BA 70 03 B8 24 25 CD 21 ?? ?? ?? ?? ?? 90 B4 2F CD 21 53 }

  condition:
    $a
}