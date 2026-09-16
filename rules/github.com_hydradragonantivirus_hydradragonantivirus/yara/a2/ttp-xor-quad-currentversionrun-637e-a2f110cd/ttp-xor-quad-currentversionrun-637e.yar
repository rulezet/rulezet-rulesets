rule TTP_XOR_QUAD_CurrentVersionRun_637e {
  strings:
    $key_637e = { 30 11 [2] 14 1f [2] 3f 33 [2] 11 11 [2] 05 0a [2] 0a 10 [2] 14 0d [2] 16 0c [2] 0d 0a [2] 11 0d [2] 0d 22 }

  condition:
    any of them
}