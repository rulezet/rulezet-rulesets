rule TTP_XOR_QUAD_CurrentVersionRun_4d71 {
  strings:
    $key_4d71 = { 1e 1e [2] 3a 10 [2] 11 3c [2] 3f 1e [2] 2b 05 [2] 24 1f [2] 3a 02 [2] 38 03 [2] 23 05 [2] 3f 02 [2] 23 2d }

  condition:
    any of them
}