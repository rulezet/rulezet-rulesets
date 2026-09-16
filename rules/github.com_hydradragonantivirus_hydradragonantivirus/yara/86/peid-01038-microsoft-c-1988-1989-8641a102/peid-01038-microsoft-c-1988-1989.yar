rule PEiD_01038_Microsoft_C__1988_1989__ {
  meta:
    description = "[Microsoft C (1988/1989)]"
    ep_only     = "true"

  strings:
    $a = { B4 30 CD 21 3C 02 73 ?? CD 20 BF ?? ?? 8B ?? ?? ?? 2B F7 81 ?? ?? ?? 72 }

  condition:
    $a
}