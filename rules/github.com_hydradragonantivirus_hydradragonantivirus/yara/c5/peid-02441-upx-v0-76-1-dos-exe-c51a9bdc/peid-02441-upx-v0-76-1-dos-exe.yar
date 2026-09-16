rule PEiD_02441_UPX_v0_76_1__dos_exe_ {
  meta:
    description = "[UPX v0.76.1 [dos exe]"
    ep_only     = "true"

  strings:
    $a = { B9 ?? ?? BE ?? ?? 89 F7 1E A9 ?? ?? 8C C8 05 ?? ?? 8E D8 05 ?? ?? 8E C0 FD F3 A5 FC }

  condition:
    $a
}