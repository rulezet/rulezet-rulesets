rule TTP_XOR_QUAD_CurrentVersionRun_265f {
  strings:
    $key_265f = { 75 30 [2] 51 3e [2] 7a 12 [2] 54 30 [2] 40 2b [2] 4f 31 [2] 51 2c [2] 53 2d [2] 48 2b [2] 54 2c [2] 48 03 }

  condition:
    any of them
}