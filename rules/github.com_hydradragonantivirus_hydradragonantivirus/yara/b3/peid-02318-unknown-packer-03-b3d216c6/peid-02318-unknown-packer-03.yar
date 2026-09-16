rule PEiD_02318_Unknown_packer__03__ {
  meta:
    description = "[Unknown packer (03)]"
    ep_only     = "true"

  strings:
    $a = { 06 1E 57 56 50 53 51 52 BD ?? ?? 0E 1F 8C }

  condition:
    $a
}