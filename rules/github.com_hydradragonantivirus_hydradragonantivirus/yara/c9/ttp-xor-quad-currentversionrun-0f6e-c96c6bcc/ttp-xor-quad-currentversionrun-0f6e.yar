rule TTP_XOR_QUAD_CurrentVersionRun_0f6e {
  strings:
    $key_0f6e = { 5c 01 [2] 78 0f [2] 53 23 [2] 7d 01 [2] 69 1a [2] 66 00 [2] 78 1d [2] 7a 1c [2] 61 1a [2] 7d 1d [2] 61 32 }

  condition:
    any of them
}