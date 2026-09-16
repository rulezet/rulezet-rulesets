rule PEiD_00544_EPW_v1_30_ {
  meta:
    description = "[EPW v1.30]"
    ep_only     = "true"

  strings:
    $a = { 06 57 1E 56 55 52 51 53 50 2E 8C 06 08 00 8C C0 83 C0 10 2E }

  condition:
    $a
}