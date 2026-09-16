rule TTP_XOR_QUAD_CurrentVersionRun_2a0c {
  strings:
    $key_2a0c = { 79 63 [2] 5d 6d [2] 76 41 [2] 58 63 [2] 4c 78 [2] 43 62 [2] 5d 7f [2] 5f 7e [2] 44 78 [2] 58 7f [2] 44 50 }

  condition:
    any of them
}