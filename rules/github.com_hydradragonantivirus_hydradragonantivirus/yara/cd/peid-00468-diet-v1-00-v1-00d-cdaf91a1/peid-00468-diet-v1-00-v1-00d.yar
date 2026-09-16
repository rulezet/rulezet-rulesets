rule PEiD_00468_DIET_v1_00__v1_00d_ {
  meta:
    description = "[DIET v1.00, v1.00d]"
    ep_only     = "true"

  strings:
    $a = { BF ?? ?? 3B FC 72 ?? B4 4C CD 21 BE ?? ?? B9 ?? ?? FD F3 A5 FC }

  condition:
    $a
}