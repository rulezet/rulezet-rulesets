rule TTP_XOR_QUAD_CurrentVersionRun_7009 {
  strings:
    $key_7009 = { 23 66 [2] 07 68 [2] 2c 44 [2] 02 66 [2] 16 7d [2] 19 67 [2] 07 7a [2] 05 7b [2] 1e 7d [2] 02 7a [2] 1e 55 }

  condition:
    any of them
}