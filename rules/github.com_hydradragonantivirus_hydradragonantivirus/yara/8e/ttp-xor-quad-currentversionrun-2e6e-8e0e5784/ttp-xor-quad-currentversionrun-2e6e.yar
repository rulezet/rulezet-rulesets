rule TTP_XOR_QUAD_CurrentVersionRun_2e6e {
  strings:
    $key_2e6e = { 7d 01 [2] 59 0f [2] 72 23 [2] 5c 01 [2] 48 1a [2] 47 00 [2] 59 1d [2] 5b 1c [2] 40 1a [2] 5c 1d [2] 40 32 }

  condition:
    any of them
}