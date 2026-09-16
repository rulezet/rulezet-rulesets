rule TTP_XOR_QUAD_CurrentVersionRun_166e {
  strings:
    $key_166e = { 45 01 [2] 61 0f [2] 4a 23 [2] 64 01 [2] 70 1a [2] 7f 00 [2] 61 1d [2] 63 1c [2] 78 1a [2] 64 1d [2] 78 32 }

  condition:
    any of them
}