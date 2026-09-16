rule PEiD_02293_Turbo_C_1990_or_Turbo_C_1988_ {
  meta:
    description = "[Turbo C 1990 or Turbo C 1988]"
    ep_only     = "true"

  strings:
    $a = { BA ?? ?? 2E 89 ?? ?? ?? B4 30 CD 21 8B ?? ?? ?? 8B ?? ?? ?? 8E DA }

  condition:
    $a
}