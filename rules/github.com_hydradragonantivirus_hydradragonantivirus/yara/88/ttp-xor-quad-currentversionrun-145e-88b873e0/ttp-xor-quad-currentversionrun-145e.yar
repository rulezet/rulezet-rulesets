rule TTP_XOR_QUAD_CurrentVersionRun_145e {
  strings:
    $key_145e = { 47 31 [2] 63 3f [2] 48 13 [2] 66 31 [2] 72 2a [2] 7d 30 [2] 63 2d [2] 61 2c [2] 7a 2a [2] 66 2d [2] 7a 02 }

  condition:
    any of them
}