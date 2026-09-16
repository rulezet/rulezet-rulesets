rule TTP_XOR_QUAD_CurrentVersionRun_326e {
  strings:
    $key_326e = { 61 01 [2] 45 0f [2] 6e 23 [2] 40 01 [2] 54 1a [2] 5b 00 [2] 45 1d [2] 47 1c [2] 5c 1a [2] 40 1d [2] 5c 32 }

  condition:
    any of them
}