rule TTP_XOR_QUAD_CurrentVersionRun_70f8 {
  strings:
    $key_70f8 = { 23 97 [2] 07 99 [2] 2c b5 [2] 02 97 [2] 16 8c [2] 19 96 [2] 07 8b [2] 05 8a [2] 1e 8c [2] 02 8b [2] 1e a4 }

  condition:
    any of them
}