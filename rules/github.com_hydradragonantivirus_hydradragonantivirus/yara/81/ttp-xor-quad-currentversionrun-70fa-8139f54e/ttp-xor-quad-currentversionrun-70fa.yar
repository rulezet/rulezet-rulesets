rule TTP_XOR_QUAD_CurrentVersionRun_70fa {
  strings:
    $key_70fa = { 23 95 [2] 07 9b [2] 2c b7 [2] 02 95 [2] 16 8e [2] 19 94 [2] 07 89 [2] 05 88 [2] 1e 8e [2] 02 89 [2] 1e a6 }

  condition:
    any of them
}