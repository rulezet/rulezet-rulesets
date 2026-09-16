rule TTP_XOR_QUAD_CurrentVersionRun_6d77 {
  strings:
    $key_6d77 = { 3e 18 [2] 1a 16 [2] 31 3a [2] 1f 18 [2] 0b 03 [2] 04 19 [2] 1a 04 [2] 18 05 [2] 03 03 [2] 1f 04 [2] 03 2b }

  condition:
    any of them
}