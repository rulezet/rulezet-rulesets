rule TTP_XOR_QUAD_CurrentVersionRun_6d19 {
  strings:
    $key_6d19 = { 3e 76 [2] 1a 78 [2] 31 54 [2] 1f 76 [2] 0b 6d [2] 04 77 [2] 1a 6a [2] 18 6b [2] 03 6d [2] 1f 6a [2] 03 45 }

  condition:
    any of them
}