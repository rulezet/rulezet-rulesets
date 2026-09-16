rule TTP_XOR_QUAD_CurrentVersionRun_2a33 {
  strings:
    $key_2a33 = { 79 5c [2] 5d 52 [2] 76 7e [2] 58 5c [2] 4c 47 [2] 43 5d [2] 5d 40 [2] 5f 41 [2] 44 47 [2] 58 40 [2] 44 6f }

  condition:
    any of them
}