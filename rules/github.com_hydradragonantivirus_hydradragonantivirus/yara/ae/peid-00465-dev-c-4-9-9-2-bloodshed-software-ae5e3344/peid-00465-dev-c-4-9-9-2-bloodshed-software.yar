rule PEiD_00465_Dev_C___4_9_9_2____Bloodshed_Software_ {
  meta:
    description = "[Dev-C++ 4.9.9.2 -> Bloodshed Software]"
    ep_only     = "true"

  strings:
    $a = { 55 89 E5 83 EC 08 C7 04 24 01 00 00 00 FF 15 ?? ?? ?? 00 E8 C8 FE FF FF 90 8D B4 26 00 00 00 00 55 89 E5 83 EC 08 C7 04 24 02 00 00 00 FF 15 ?? ?? ?? 00 E8 A8 FE FF FF 90 8D B4 26 00 00 00 00 55 8B 0D ?? ?? ?? 00 89 E5 5D FF E1 8D 74 26 00 55 8B 0D }

  condition:
    $a
}