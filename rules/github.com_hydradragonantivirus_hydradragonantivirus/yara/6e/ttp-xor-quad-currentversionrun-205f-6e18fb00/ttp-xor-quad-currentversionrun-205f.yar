rule TTP_XOR_QUAD_CurrentVersionRun_205f {
  strings:
    $key_205f = { 73 30 [2] 57 3e [2] 7c 12 [2] 52 30 [2] 46 2b [2] 49 31 [2] 57 2c [2] 55 2d [2] 4e 2b [2] 52 2c [2] 4e 03 }

  condition:
    any of them
}