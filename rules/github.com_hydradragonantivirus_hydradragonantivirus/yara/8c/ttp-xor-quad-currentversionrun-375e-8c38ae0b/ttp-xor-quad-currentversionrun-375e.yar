rule TTP_XOR_QUAD_CurrentVersionRun_375e {
  strings:
    $key_375e = { 64 31 [2] 40 3f [2] 6b 13 [2] 45 31 [2] 51 2a [2] 5e 30 [2] 40 2d [2] 42 2c [2] 59 2a [2] 45 2d [2] 59 02 }

  condition:
    any of them
}