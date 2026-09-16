rule TTP_XOR_QUAD_CurrentVersionRun_2d7d {
  strings:
    $key_2d7d = { 7e 12 [2] 5a 1c [2] 71 30 [2] 5f 12 [2] 4b 09 [2] 44 13 [2] 5a 0e [2] 58 0f [2] 43 09 [2] 5f 0e [2] 43 21 }

  condition:
    any of them
}