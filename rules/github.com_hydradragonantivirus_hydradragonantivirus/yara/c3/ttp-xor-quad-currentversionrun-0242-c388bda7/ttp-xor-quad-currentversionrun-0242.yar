rule TTP_XOR_QUAD_CurrentVersionRun_0242 {
  strings:
    $key_0242 = { 51 2d [2] 75 23 [2] 5e 0f [2] 70 2d [2] 64 36 [2] 6b 2c [2] 75 31 [2] 77 30 [2] 6c 36 [2] 70 31 [2] 6c 1e }

  condition:
    any of them
}