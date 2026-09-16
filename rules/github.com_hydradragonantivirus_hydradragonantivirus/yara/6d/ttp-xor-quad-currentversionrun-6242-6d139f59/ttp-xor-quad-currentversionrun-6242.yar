rule TTP_XOR_QUAD_CurrentVersionRun_6242 {
  strings:
    $key_6242 = { 31 2d [2] 15 23 [2] 3e 0f [2] 10 2d [2] 04 36 [2] 0b 2c [2] 15 31 [2] 17 30 [2] 0c 36 [2] 10 31 [2] 0c 1e }

  condition:
    any of them
}