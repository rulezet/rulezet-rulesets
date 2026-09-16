rule TTP_XOR_QUAD_CurrentVersionRun_1242 {
  strings:
    $key_1242 = { 41 2d [2] 65 23 [2] 4e 0f [2] 60 2d [2] 74 36 [2] 7b 2c [2] 65 31 [2] 67 30 [2] 7c 36 [2] 60 31 [2] 7c 1e }

  condition:
    any of them
}