rule PEiD_00405_Cracked_by_Autohack__2__ {
  meta:
    description = "[Cracked by Autohack (2)]"
    ep_only     = "true"

  strings:
    $a = { 0E 1F B4 09 BA ?? ?? CD 21 FA 8E 06 ?? ?? BE ?? ?? 8B 0E ?? ?? 83 F9 }

  condition:
    $a
}