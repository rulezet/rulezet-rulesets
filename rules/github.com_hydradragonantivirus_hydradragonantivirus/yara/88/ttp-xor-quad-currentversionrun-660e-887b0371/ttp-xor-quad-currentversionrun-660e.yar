rule TTP_XOR_QUAD_CurrentVersionRun_660e {
  strings:
    $key_660e = { 35 61 [2] 11 6f [2] 3a 43 [2] 14 61 [2] 00 7a [2] 0f 60 [2] 11 7d [2] 13 7c [2] 08 7a [2] 14 7d [2] 08 52 }

  condition:
    any of them
}