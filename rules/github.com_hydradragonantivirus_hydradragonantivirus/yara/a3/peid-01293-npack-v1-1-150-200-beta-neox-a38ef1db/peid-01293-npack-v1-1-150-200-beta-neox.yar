rule PEiD_01293_nPack_v1_1_150_200_Beta____NEOx_ {
  meta:
    description = "[nPack v1.1 150-200 Beta -> NEOx]"
    ep_only     = "true"

  strings:
    $a = { 83 3D 40 ?? ?? ?? 00 75 05 E9 01 00 00 00 C3 E8 41 00 00 00 B8 80 ?? ?? ?? 2B 05 08 ?? ?? ?? A3 3C ?? ?? 00 E8 5E 00 00 00 E8 E0 01 00 00 E8 EC 06 00 00 E8 F7 05 00 00 }

  condition:
    $a
}