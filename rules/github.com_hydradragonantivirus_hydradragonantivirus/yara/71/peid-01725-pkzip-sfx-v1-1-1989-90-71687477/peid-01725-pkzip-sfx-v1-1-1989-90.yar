rule PEiD_01725_PKZIP_SFX_v1_1_1989_90_ {
  meta:
    description = "[PKZIP-SFX v1.1 1989-90]"
    ep_only     = "true"

  strings:
    $a = { FC 2E 8C 0E ?? ?? A1 ?? ?? 8C CB 81 C3 ?? ?? 3B C3 72 ?? 2D ?? ?? 2D ?? ?? FA BC ?? ?? 8E D0 FB }

  condition:
    $a
}