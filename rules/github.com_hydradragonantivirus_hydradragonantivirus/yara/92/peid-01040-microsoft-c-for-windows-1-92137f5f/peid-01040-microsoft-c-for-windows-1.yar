rule PEiD_01040_Microsoft_C_for_Windows__1__ {
  meta:
    description = "[Microsoft C for Windows (1)]"
    ep_only     = "true"

  strings:
    $a = { 33 ED 55 9A ?? ?? ?? ?? 0B C0 74 }

  condition:
    $a
}