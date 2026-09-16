rule TTP_XOR_QUAD_CurrentVersionRun_5b1e {
  strings:
    $key_5b1e = { 08 71 [2] 2c 7f [2] 07 53 [2] 29 71 [2] 3d 6a [2] 32 70 [2] 2c 6d [2] 2e 6c [2] 35 6a [2] 29 6d [2] 35 42 }

  condition:
    any of them
}