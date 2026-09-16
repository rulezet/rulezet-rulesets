rule PEiD_02033_SCRAM__vC5_ {
  meta:
    description = "[SCRAM! vC5]"
    ep_only     = "true"

  strings:
    $a = { B8 ?? ?? 50 9D 9C 58 25 ?? ?? 75 ?? BA ?? ?? B4 09 CD 21 CD 20 }

  condition:
    $a
}