rule TTP_XOR_QUAD_CurrentVersionRun_2afc {
  strings:
    $key_2afc = { 79 93 [2] 5d 9d [2] 76 b1 [2] 58 93 [2] 4c 88 [2] 43 92 [2] 5d 8f [2] 5f 8e [2] 44 88 [2] 58 8f [2] 44 a0 }

  condition:
    any of them
}