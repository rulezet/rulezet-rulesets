rule TTP_XOR_QUAD_CurrentVersionRun_5efa {
  strings:
    $key_5efa = { 0d 95 [2] 29 9b [2] 02 b7 [2] 2c 95 [2] 38 8e [2] 37 94 [2] 29 89 [2] 2b 88 [2] 30 8e [2] 2c 89 [2] 30 a6 }

  condition:
    any of them
}