rule TTP_XOR_QUAD_CurrentVersionRun_f95e {
  strings:
    $key_f95e = { aa 31 [2] 8e 3f [2] a5 13 [2] 8b 31 [2] 9f 2a [2] 90 30 [2] 8e 2d [2] 8c 2c [2] 97 2a [2] 8b 2d [2] 97 02 }

  condition:
    any of them
}