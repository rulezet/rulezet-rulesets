rule TTP_XOR_QUAD_CurrentVersionRun_2a6a {
  strings:
    $key_2a6a = { 79 05 [2] 5d 0b [2] 76 27 [2] 58 05 [2] 4c 1e [2] 43 04 [2] 5d 19 [2] 5f 18 [2] 44 1e [2] 58 19 [2] 44 36 }

  condition:
    any of them
}