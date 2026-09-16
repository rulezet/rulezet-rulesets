rule TTP_XOR_QUAD_CurrentVersionRun_656e {
  strings:
    $key_656e = { 36 01 [2] 12 0f [2] 39 23 [2] 17 01 [2] 03 1a [2] 0c 00 [2] 12 1d [2] 10 1c [2] 0b 1a [2] 17 1d [2] 0b 32 }

  condition:
    any of them
}