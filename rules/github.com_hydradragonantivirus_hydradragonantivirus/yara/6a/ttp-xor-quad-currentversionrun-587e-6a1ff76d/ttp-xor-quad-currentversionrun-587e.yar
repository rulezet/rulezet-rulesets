rule TTP_XOR_QUAD_CurrentVersionRun_587e {
  strings:
    $key_587e = { 0b 11 [2] 2f 1f [2] 04 33 [2] 2a 11 [2] 3e 0a [2] 31 10 [2] 2f 0d [2] 2d 0c [2] 36 0a [2] 2a 0d [2] 36 22 }

  condition:
    any of them
}