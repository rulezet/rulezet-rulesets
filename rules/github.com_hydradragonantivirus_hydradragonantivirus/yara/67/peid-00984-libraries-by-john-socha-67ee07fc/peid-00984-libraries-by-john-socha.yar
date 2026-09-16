rule PEiD_00984_Libraries_by_John_Socha_ {
  meta:
    description = "[Libraries by John Socha]"
    ep_only     = "true"

  strings:
    $a = { BB ?? ?? 8E DB 2E 89 ?? ?? ?? 8D ?? ?? ?? 25 ?? ?? FA 8E D3 8B E0 FB 26 A1 A3 ?? ?? B4 30 CD 21 }

  condition:
    $a
}