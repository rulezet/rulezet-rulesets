rule PEiD_03437_WARNING____TROJAN____XiaoHui_ {
  meta:
    description = "[WARNING -> TROJAN -> XiaoHui]"
    ep_only     = "true"

  strings:
    $a = { 60 9C E8 00 00 00 00 5D B8 ?? 85 40 00 2D ?? 85 40 00 }

  condition:
    $a
}