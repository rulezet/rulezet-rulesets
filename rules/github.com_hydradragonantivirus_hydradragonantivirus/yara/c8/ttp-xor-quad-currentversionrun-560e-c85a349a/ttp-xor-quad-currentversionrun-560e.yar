rule TTP_XOR_QUAD_CurrentVersionRun_560e {
  strings:
    $key_560e = { 05 61 [2] 21 6f [2] 0a 43 [2] 24 61 [2] 30 7a [2] 3f 60 [2] 21 7d [2] 23 7c [2] 38 7a [2] 24 7d [2] 38 52 }

  condition:
    any of them
}