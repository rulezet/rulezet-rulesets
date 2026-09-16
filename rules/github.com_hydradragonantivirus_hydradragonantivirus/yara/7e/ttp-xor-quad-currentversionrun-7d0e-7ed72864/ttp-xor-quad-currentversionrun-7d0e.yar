rule TTP_XOR_QUAD_CurrentVersionRun_7d0e {
  strings:
    $key_7d0e = { 2e 61 [2] 0a 6f [2] 21 43 [2] 0f 61 [2] 1b 7a [2] 14 60 [2] 0a 7d [2] 08 7c [2] 13 7a [2] 0f 7d [2] 13 52 }

  condition:
    any of them
}