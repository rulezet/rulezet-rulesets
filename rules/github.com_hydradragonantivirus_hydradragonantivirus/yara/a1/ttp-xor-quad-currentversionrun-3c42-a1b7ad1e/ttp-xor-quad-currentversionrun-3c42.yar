rule TTP_XOR_QUAD_CurrentVersionRun_3c42 {
  strings:
    $key_3c42 = { 6f 2d [2] 4b 23 [2] 60 0f [2] 4e 2d [2] 5a 36 [2] 55 2c [2] 4b 31 [2] 49 30 [2] 52 36 [2] 4e 31 [2] 52 1e }

  condition:
    any of them
}