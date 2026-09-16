rule TTP_XOR_QUAD_CurrentVersionRun_7a2c {
  strings:
    $key_7a2c = { 29 43 [2] 0d 4d [2] 26 61 [2] 08 43 [2] 1c 58 [2] 13 42 [2] 0d 5f [2] 0f 5e [2] 14 58 [2] 08 5f [2] 14 70 }

  condition:
    any of them
}