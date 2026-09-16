rule TTP_XOR_QUAD_CurrentVersionRun_f86e {
  strings:
    $key_f86e = { ab 01 [2] 8f 0f [2] a4 23 [2] 8a 01 [2] 9e 1a [2] 91 00 [2] 8f 1d [2] 8d 1c [2] 96 1a [2] 8a 1d [2] 96 32 }

  condition:
    any of them
}