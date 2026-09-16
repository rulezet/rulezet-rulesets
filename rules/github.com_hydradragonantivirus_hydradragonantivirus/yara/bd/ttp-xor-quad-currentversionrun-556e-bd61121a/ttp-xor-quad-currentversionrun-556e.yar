rule TTP_XOR_QUAD_CurrentVersionRun_556e {
  strings:
    $key_556e = { 06 01 [2] 22 0f [2] 09 23 [2] 27 01 [2] 33 1a [2] 3c 00 [2] 22 1d [2] 20 1c [2] 3b 1a [2] 27 1d [2] 3b 32 }

  condition:
    any of them
}