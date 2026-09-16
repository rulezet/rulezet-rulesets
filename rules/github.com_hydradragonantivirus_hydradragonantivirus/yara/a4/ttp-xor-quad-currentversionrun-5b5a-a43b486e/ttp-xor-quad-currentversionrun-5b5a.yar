rule TTP_XOR_QUAD_CurrentVersionRun_5b5a {
  strings:
    $key_5b5a = { 08 35 [2] 2c 3b [2] 07 17 [2] 29 35 [2] 3d 2e [2] 32 34 [2] 2c 29 [2] 2e 28 [2] 35 2e [2] 29 29 [2] 35 06 }

  condition:
    any of them
}