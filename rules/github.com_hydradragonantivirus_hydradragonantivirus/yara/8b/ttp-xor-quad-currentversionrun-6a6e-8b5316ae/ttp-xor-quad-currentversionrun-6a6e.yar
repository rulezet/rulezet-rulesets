rule TTP_XOR_QUAD_CurrentVersionRun_6a6e {
  strings:
    $key_6a6e = { 39 01 [2] 1d 0f [2] 36 23 [2] 18 01 [2] 0c 1a [2] 03 00 [2] 1d 1d [2] 1f 1c [2] 04 1a [2] 18 1d [2] 04 32 }

  condition:
    any of them
}