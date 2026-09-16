rule TTP_XOR_QUAD_CurrentVersionRun_7d2c {
  strings:
    $key_7d2c = { 2e 43 [2] 0a 4d [2] 21 61 [2] 0f 43 [2] 1b 58 [2] 14 42 [2] 0a 5f [2] 08 5e [2] 13 58 [2] 0f 5f [2] 13 70 }

  condition:
    any of them
}