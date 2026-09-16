rule TTP_XOR_QUAD_CurrentVersionRun_f642 {
  strings:
    $key_f642 = { a5 2d [2] 81 23 [2] aa 0f [2] 84 2d [2] 90 36 [2] 9f 2c [2] 81 31 [2] 83 30 [2] 98 36 [2] 84 31 [2] 98 1e }

  condition:
    any of them
}