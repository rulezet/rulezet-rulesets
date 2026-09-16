rule TTP_XOR_QUAD_CurrentVersionRun_5b0f {
  strings:
    $key_5b0f = { 08 60 [2] 2c 6e [2] 07 42 [2] 29 60 [2] 3d 7b [2] 32 61 [2] 2c 7c [2] 2e 7d [2] 35 7b [2] 29 7c [2] 35 53 }

  condition:
    any of them
}