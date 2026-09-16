rule TTP_XOR_QUAD_CurrentVersionRun_7a0e {
  strings:
    $key_7a0e = { 29 61 [2] 0d 6f [2] 26 43 [2] 08 61 [2] 1c 7a [2] 13 60 [2] 0d 7d [2] 0f 7c [2] 14 7a [2] 08 7d [2] 14 52 }

  condition:
    any of them
}