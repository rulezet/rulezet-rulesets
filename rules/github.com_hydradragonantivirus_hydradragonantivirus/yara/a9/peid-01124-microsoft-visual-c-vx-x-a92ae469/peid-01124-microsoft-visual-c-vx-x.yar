rule PEiD_01124_Microsoft_Visual_C___vx_x_ {
  meta:
    description = "[Microsoft Visual C++ vx.x]"
    ep_only     = "true"

  strings:
    $a = { 55 8B EC 56 57 BF ?? ?? ?? ?? 8B ?? ?? 3B F7 0F }

  condition:
    $a
}