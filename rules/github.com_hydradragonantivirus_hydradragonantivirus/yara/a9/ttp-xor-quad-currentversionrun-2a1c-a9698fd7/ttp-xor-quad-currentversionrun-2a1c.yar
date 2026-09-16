rule TTP_XOR_QUAD_CurrentVersionRun_2a1c {
  strings:
    $key_2a1c = { 79 73 [2] 5d 7d [2] 76 51 [2] 58 73 [2] 4c 68 [2] 43 72 [2] 5d 6f [2] 5f 6e [2] 44 68 [2] 58 6f [2] 44 40 }

  condition:
    any of them
}