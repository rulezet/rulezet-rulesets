rule TTP_XOR_QUAD_CurrentVersionRun_e242 {
  strings:
    $key_e242 = { b1 2d [2] 95 23 [2] be 0f [2] 90 2d [2] 84 36 [2] 8b 2c [2] 95 31 [2] 97 30 [2] 8c 36 [2] 90 31 [2] 8c 1e }

  condition:
    any of them
}