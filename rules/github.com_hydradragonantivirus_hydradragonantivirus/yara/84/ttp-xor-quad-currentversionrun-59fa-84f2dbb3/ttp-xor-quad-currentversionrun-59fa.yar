rule TTP_XOR_QUAD_CurrentVersionRun_59fa {
  strings:
    $key_59fa = { 0a 95 [2] 2e 9b [2] 05 b7 [2] 2b 95 [2] 3f 8e [2] 30 94 [2] 2e 89 [2] 2c 88 [2] 37 8e [2] 2b 89 [2] 37 a6 }

  condition:
    any of them
}