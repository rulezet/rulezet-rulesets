rule TTP_XOR_QUAD_CurrentVersionRun_7e6e {
  strings:
    $key_7e6e = { 2d 01 [2] 09 0f [2] 22 23 [2] 0c 01 [2] 18 1a [2] 17 00 [2] 09 1d [2] 0b 1c [2] 10 1a [2] 0c 1d [2] 10 32 }

  condition:
    any of them
}