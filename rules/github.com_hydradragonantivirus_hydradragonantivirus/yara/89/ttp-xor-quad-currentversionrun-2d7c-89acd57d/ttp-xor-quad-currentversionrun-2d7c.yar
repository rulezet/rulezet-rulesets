rule TTP_XOR_QUAD_CurrentVersionRun_2d7c {
  strings:
    $key_2d7c = { 7e 13 [2] 5a 1d [2] 71 31 [2] 5f 13 [2] 4b 08 [2] 44 12 [2] 5a 0f [2] 58 0e [2] 43 08 [2] 5f 0f [2] 43 20 }

  condition:
    any of them
}