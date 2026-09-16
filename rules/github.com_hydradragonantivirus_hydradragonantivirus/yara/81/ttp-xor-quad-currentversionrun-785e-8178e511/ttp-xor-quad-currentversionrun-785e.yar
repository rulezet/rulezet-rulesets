rule TTP_XOR_QUAD_CurrentVersionRun_785e {
  strings:
    $key_785e = { 2b 31 [2] 0f 3f [2] 24 13 [2] 0a 31 [2] 1e 2a [2] 11 30 [2] 0f 2d [2] 0d 2c [2] 16 2a [2] 0a 2d [2] 16 02 }

  condition:
    any of them
}