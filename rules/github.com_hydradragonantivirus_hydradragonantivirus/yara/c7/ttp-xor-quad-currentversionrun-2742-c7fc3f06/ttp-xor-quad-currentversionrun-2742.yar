rule TTP_XOR_QUAD_CurrentVersionRun_2742 {
  strings:
    $key_2742 = { 74 2d [2] 50 23 [2] 7b 0f [2] 55 2d [2] 41 36 [2] 4e 2c [2] 50 31 [2] 52 30 [2] 49 36 [2] 55 31 [2] 49 1e }

  condition:
    any of them
}