rule PEiD_02300_Turbo_Pascal_Help_File_ {
  meta:
    description = "[Turbo Pascal Help File]"
    ep_only     = "false"

  strings:
    $a = { 54 55 52 ?? ?? ?? 50 41 53 ?? ?? ?? ?? 48 45 4C 50 }

  condition:
    $a
}