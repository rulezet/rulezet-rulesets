rule TTP_XOR_QUAD_CurrentVersionRun_5b2a {
  strings:
    $key_5b2a = { 08 45 [2] 2c 4b [2] 07 67 [2] 29 45 [2] 3d 5e [2] 32 44 [2] 2c 59 [2] 2e 58 [2] 35 5e [2] 29 59 [2] 35 76 }

  condition:
    any of them
}