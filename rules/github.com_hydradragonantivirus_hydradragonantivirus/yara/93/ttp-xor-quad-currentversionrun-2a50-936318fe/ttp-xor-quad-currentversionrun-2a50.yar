rule TTP_XOR_QUAD_CurrentVersionRun_2a50 {
  strings:
    $key_2a50 = { 79 3f [2] 5d 31 [2] 76 1d [2] 58 3f [2] 4c 24 [2] 43 3e [2] 5d 23 [2] 5f 22 [2] 44 24 [2] 58 23 [2] 44 0c }

  condition:
    any of them
}