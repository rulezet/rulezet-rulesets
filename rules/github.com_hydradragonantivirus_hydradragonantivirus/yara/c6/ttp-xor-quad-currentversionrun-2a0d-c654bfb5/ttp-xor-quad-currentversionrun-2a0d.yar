rule TTP_XOR_QUAD_CurrentVersionRun_2a0d {
  strings:
    $key_2a0d = { 79 62 [2] 5d 6c [2] 76 40 [2] 58 62 [2] 4c 79 [2] 43 63 [2] 5d 7e [2] 5f 7f [2] 44 79 [2] 58 7e [2] 44 51 }

  condition:
    any of them
}