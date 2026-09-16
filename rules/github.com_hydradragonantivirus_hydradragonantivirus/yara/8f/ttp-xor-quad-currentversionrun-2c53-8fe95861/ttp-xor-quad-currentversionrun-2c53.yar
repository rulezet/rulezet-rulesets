rule TTP_XOR_QUAD_CurrentVersionRun_2c53 {
  strings:
    $key_2c53 = { 7f 3c [2] 5b 32 [2] 70 1e [2] 5e 3c [2] 4a 27 [2] 45 3d [2] 5b 20 [2] 59 21 [2] 42 27 [2] 5e 20 [2] 42 0f }

  condition:
    any of them
}