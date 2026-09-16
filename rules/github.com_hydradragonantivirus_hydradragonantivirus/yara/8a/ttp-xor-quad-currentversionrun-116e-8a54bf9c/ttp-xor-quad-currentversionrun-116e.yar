rule TTP_XOR_QUAD_CurrentVersionRun_116e {
  strings:
    $key_116e = { 42 01 [2] 66 0f [2] 4d 23 [2] 63 01 [2] 77 1a [2] 78 00 [2] 66 1d [2] 64 1c [2] 7f 1a [2] 63 1d [2] 7f 32 }

  condition:
    any of them
}