rule TTP_XOR_QUAD_CurrentVersionRun_066e {
  strings:
    $key_066e = { 55 01 [2] 71 0f [2] 5a 23 [2] 74 01 [2] 60 1a [2] 6f 00 [2] 71 1d [2] 73 1c [2] 68 1a [2] 74 1d [2] 68 32 }

  condition:
    any of them
}