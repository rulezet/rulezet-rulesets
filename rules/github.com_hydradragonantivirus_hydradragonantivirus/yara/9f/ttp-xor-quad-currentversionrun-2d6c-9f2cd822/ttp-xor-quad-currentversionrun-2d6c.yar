rule TTP_XOR_QUAD_CurrentVersionRun_2d6c {
  strings:
    $key_2d6c = { 7e 03 [2] 5a 0d [2] 71 21 [2] 5f 03 [2] 4b 18 [2] 44 02 [2] 5a 1f [2] 58 1e [2] 43 18 [2] 5f 1f [2] 43 30 }

  condition:
    any of them
}