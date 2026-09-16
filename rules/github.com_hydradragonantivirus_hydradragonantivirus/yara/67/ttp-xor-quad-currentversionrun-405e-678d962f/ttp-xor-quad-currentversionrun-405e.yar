rule TTP_XOR_QUAD_CurrentVersionRun_405e {
  strings:
    $key_405e = { 13 31 [2] 37 3f [2] 1c 13 [2] 32 31 [2] 26 2a [2] 29 30 [2] 37 2d [2] 35 2c [2] 2e 2a [2] 32 2d [2] 2e 02 }

  condition:
    any of them
}