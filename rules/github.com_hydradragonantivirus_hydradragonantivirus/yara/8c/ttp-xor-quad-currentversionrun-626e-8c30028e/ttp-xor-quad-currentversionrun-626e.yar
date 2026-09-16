rule TTP_XOR_QUAD_CurrentVersionRun_626e {
  strings:
    $key_626e = { 31 01 [2] 15 0f [2] 3e 23 [2] 10 01 [2] 04 1a [2] 0b 00 [2] 15 1d [2] 17 1c [2] 0c 1a [2] 10 1d [2] 0c 32 }

  condition:
    any of them
}