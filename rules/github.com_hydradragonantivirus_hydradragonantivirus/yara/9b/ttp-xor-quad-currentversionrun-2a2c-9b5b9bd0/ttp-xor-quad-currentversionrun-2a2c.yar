rule TTP_XOR_QUAD_CurrentVersionRun_2a2c {
  strings:
    $key_2a2c = { 79 43 [2] 5d 4d [2] 76 61 [2] 58 43 [2] 4c 58 [2] 43 42 [2] 5d 5f [2] 5f 5e [2] 44 58 [2] 58 5f [2] 44 70 }

  condition:
    any of them
}