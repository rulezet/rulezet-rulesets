rule PEiD_00122_Armadillo_3_X_5_X____Silicon_Realms_Toolworks_ {
  meta:
    description = "[Armadillo 3.X-5.X -> Silicon Realms Toolworks]"
    ep_only     = "true"

  strings:
    $a = { 60 E8 00 00 00 00 5D 50 51 0F CA F7 D2 9C F7 D2 0F CA EB 0F B9 EB 0F B8 EB 07 B9 EB 0F 90 EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC E9 9D 0F C9 8B CA F7 D1 59 58 50 51 0F CA F7 D2 9C F7 D2 0F CA EB 0F B9 EB 0F B8 EB 07 B9 EB 0F 90 EB 08 }

  condition:
    $a
}