rule TTP_XOR_QUAD_CurrentVersionRun_365f {
  strings:
    $key_365f = { 65 30 [2] 41 3e [2] 6a 12 [2] 44 30 [2] 50 2b [2] 5f 31 [2] 41 2c [2] 43 2d [2] 58 2b [2] 44 2c [2] 58 03 }

  condition:
    any of them
}