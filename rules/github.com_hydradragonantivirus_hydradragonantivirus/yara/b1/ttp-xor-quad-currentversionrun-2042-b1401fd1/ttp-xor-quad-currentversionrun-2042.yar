rule TTP_XOR_QUAD_CurrentVersionRun_2042 {
  strings:
    $key_2042 = { 73 2d [2] 57 23 [2] 7c 0f [2] 52 2d [2] 46 36 [2] 49 2c [2] 57 31 [2] 55 30 [2] 4e 36 [2] 52 31 [2] 4e 1e }

  condition:
    any of them
}