rule TTP_XOR_QUAD_CurrentVersionRun_e37e {
  strings:
    $key_e37e = { b0 11 [2] 94 1f [2] bf 33 [2] 91 11 [2] 85 0a [2] 8a 10 [2] 94 0d [2] 96 0c [2] 8d 0a [2] 91 0d [2] 8d 22 }

  condition:
    any of them
}