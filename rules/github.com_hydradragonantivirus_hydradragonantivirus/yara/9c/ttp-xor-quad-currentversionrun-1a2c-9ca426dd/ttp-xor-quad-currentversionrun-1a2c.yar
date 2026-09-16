rule TTP_XOR_QUAD_CurrentVersionRun_1a2c {
  strings:
    $key_1a2c = { 49 43 [2] 6d 4d [2] 46 61 [2] 68 43 [2] 7c 58 [2] 73 42 [2] 6d 5f [2] 6f 5e [2] 74 58 [2] 68 5f [2] 74 70 }

  condition:
    any of them
}