rule TTP_XOR_QUAD_CurrentVersionRun_6742 {
  strings:
    $key_6742 = { 34 2d [2] 10 23 [2] 3b 0f [2] 15 2d [2] 01 36 [2] 0e 2c [2] 10 31 [2] 12 30 [2] 09 36 [2] 15 31 [2] 09 1e }

  condition:
    any of them
}