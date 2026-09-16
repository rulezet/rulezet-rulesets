rule TTP_XOR_QUAD_CurrentVersionRun_165e {
  strings:
    $key_165e = { 45 31 [2] 61 3f [2] 4a 13 [2] 64 31 [2] 70 2a [2] 7f 30 [2] 61 2d [2] 63 2c [2] 78 2a [2] 64 2d [2] 78 02 }

  condition:
    any of them
}