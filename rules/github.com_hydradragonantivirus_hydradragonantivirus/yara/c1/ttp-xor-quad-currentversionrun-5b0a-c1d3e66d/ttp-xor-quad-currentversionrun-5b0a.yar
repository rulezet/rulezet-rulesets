rule TTP_XOR_QUAD_CurrentVersionRun_5b0a {
  strings:
    $key_5b0a = { 08 65 [2] 2c 6b [2] 07 47 [2] 29 65 [2] 3d 7e [2] 32 64 [2] 2c 79 [2] 2e 78 [2] 35 7e [2] 29 79 [2] 35 56 }

  condition:
    any of them
}