rule TTP_XOR_QUAD_CurrentVersionRun_0860 {
  strings:
    $key_0860 = { 5b 0f [2] 7f 01 [2] 54 2d [2] 7a 0f [2] 6e 14 [2] 61 0e [2] 7f 13 [2] 7d 12 [2] 66 14 [2] 7a 13 [2] 66 3c }

  condition:
    any of them
}