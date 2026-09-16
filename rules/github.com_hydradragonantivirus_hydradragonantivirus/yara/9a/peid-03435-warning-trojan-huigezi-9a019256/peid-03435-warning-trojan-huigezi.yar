rule PEiD_03435_WARNING____TROJAN____HuiGeZi_ {
  meta:
    description = "[WARNING -> TROJAN -> HuiGeZi]"
    ep_only     = "true"

  strings:
    $a = { 55 8B EC 81 C4 ?? FE FF FF 53 56 57 33 C0 89 85 ?? FE FF FF }

  condition:
    $a
}