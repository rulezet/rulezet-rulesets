rule TTP_XOR_QUAD_CurrentVersionRun_f142 {
  strings:
    $key_f142 = { a2 2d [2] 86 23 [2] ad 0f [2] 83 2d [2] 97 36 [2] 98 2c [2] 86 31 [2] 84 30 [2] 9f 36 [2] 83 31 [2] 9f 1e }

  condition:
    any of them
}