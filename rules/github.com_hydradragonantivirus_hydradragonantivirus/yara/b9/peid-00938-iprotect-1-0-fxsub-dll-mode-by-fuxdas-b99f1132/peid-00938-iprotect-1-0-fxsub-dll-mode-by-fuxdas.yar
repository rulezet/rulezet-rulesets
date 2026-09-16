rule PEiD_00938_IProtect_1_0__FxSub_dll_mode____by_FuXdas_ {
  meta:
    description = "[IProtect 1.0 (FxSub.dll mode) - by FuXdas]"
    ep_only     = "true"

  strings:
    $a = { EB 33 2E 46 55 58 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 46 78 53 75 62 2E 64 6C 6C 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? 00 60 E8 00 00 00 00 5D 81 ED B6 13 40 00 FF 74 24 20 E8 40 00 00 00 0B C0 74 2F 89 85 A8 13 40 00 }

  condition:
    $a
}