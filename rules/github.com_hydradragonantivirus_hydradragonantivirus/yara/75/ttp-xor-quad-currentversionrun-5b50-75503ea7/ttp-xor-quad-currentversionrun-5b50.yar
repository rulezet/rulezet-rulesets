rule TTP_XOR_QUAD_CurrentVersionRun_5b50 {
  strings:
    $key_5b50 = { 08 3f [2] 2c 31 [2] 07 1d [2] 29 3f [2] 3d 24 [2] 32 3e [2] 2c 23 [2] 2e 22 [2] 35 24 [2] 29 23 [2] 35 0c }

  condition:
    any of them
}