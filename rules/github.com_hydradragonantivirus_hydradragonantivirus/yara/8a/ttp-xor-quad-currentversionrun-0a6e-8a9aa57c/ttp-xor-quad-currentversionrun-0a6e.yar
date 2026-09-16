rule TTP_XOR_QUAD_CurrentVersionRun_0a6e {
  strings:
    $key_0a6e = { 59 01 [2] 7d 0f [2] 56 23 [2] 78 01 [2] 6c 1a [2] 63 00 [2] 7d 1d [2] 7f 1c [2] 64 1a [2] 78 1d [2] 64 32 }

  condition:
    any of them
}