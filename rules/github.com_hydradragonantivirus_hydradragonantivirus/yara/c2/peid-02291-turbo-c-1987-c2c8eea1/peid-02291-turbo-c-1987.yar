rule PEiD_02291_Turbo_C_1987_ {
  meta:
    description = "[Turbo C 1987]"
    ep_only     = "true"

  strings:
    $a = { FB 8C CA 2E 89 16 ?? ?? B4 30 CD 21 8B 2E ?? ?? 8B 1E ?? ?? 8E DA }

  condition:
    $a
}