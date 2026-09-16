rule TTP_XOR_QUAD_CurrentVersionRun_5b2f {
  strings:
    $key_5b2f = { 08 40 [2] 2c 4e [2] 07 62 [2] 29 40 [2] 3d 5b [2] 32 41 [2] 2c 5c [2] 2e 5d [2] 35 5b [2] 29 5c [2] 35 73 }

  condition:
    any of them
}