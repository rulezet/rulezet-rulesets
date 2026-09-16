rule TTP_XOR_QUAD_CurrentVersionRun_3075 {
  strings:
    $key_3075 = { 63 1a [2] 47 14 [2] 6c 38 [2] 42 1a [2] 56 01 [2] 59 1b [2] 47 06 [2] 45 07 [2] 5e 01 [2] 42 06 [2] 5e 29 }

  condition:
    any of them
}