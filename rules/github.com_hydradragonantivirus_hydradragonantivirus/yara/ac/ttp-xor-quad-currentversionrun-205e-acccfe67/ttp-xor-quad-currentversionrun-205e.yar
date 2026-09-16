rule TTP_XOR_QUAD_CurrentVersionRun_205e {
  strings:
    $key_205e = { 73 31 [2] 57 3f [2] 7c 13 [2] 52 31 [2] 46 2a [2] 49 30 [2] 57 2d [2] 55 2c [2] 4e 2a [2] 52 2d [2] 4e 02 }

  condition:
    any of them
}