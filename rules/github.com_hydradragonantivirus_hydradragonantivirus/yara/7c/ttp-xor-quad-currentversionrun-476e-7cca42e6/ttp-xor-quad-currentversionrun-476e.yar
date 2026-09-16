rule TTP_XOR_QUAD_CurrentVersionRun_476e {
  strings:
    $key_476e = { 14 01 [2] 30 0f [2] 1b 23 [2] 35 01 [2] 21 1a [2] 2e 00 [2] 30 1d [2] 32 1c [2] 29 1a [2] 35 1d [2] 29 32 }

  condition:
    any of them
}