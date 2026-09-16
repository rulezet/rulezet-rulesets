rule TTP_XOR_QUAD_CurrentVersionRun_6d2e {
  strings:
    $key_6d2e = { 3e 41 [2] 1a 4f [2] 31 63 [2] 1f 41 [2] 0b 5a [2] 04 40 [2] 1a 5d [2] 18 5c [2] 03 5a [2] 1f 5d [2] 03 72 }

  condition:
    any of them
}