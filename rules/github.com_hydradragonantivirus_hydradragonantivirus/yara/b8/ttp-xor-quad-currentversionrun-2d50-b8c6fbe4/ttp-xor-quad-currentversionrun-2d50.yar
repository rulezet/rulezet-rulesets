rule TTP_XOR_QUAD_CurrentVersionRun_2d50 {
  strings:
    $key_2d50 = { 7e 3f [2] 5a 31 [2] 71 1d [2] 5f 3f [2] 4b 24 [2] 44 3e [2] 5a 23 [2] 58 22 [2] 43 24 [2] 5f 23 [2] 43 0c }

  condition:
    any of them
}