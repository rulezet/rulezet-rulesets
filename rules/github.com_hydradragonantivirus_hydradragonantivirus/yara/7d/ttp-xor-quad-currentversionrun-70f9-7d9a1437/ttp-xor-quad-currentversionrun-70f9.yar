rule TTP_XOR_QUAD_CurrentVersionRun_70f9 {
  strings:
    $key_70f9 = { 23 96 [2] 07 98 [2] 2c b4 [2] 02 96 [2] 16 8d [2] 19 97 [2] 07 8a [2] 05 8b [2] 1e 8d [2] 02 8a [2] 1e a5 }

  condition:
    any of them
}