rule PEiD_02323_Unknown_packer__08__ {
  meta:
    description = "[Unknown packer (08)]"
    ep_only     = "true"

  strings:
    $a = { 8B C4 2D ?? ?? 24 00 8B F8 57 B9 ?? ?? BE ?? ?? F3 A5 FD C3 97 4F 4F }

  condition:
    $a
}