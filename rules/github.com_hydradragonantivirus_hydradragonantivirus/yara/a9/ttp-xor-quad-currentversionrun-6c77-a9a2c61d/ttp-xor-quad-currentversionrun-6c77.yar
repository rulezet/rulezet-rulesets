rule TTP_XOR_QUAD_CurrentVersionRun_6c77 {
  strings:
    $key_6c77 = { 3f 18 [2] 1b 16 [2] 30 3a [2] 1e 18 [2] 0a 03 [2] 05 19 [2] 1b 04 [2] 19 05 [2] 02 03 [2] 1e 04 [2] 02 2b }

  condition:
    any of them
}