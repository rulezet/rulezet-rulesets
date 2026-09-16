rule TTP_XOR_QUAD_CurrentVersionRun_423f {
  strings:
    $key_423f = { 11 50 [2] 35 5e [2] 1e 72 [2] 30 50 [2] 24 4b [2] 2b 51 [2] 35 4c [2] 37 4d [2] 2c 4b [2] 30 4c [2] 2c 63 }

  condition:
    any of them
}