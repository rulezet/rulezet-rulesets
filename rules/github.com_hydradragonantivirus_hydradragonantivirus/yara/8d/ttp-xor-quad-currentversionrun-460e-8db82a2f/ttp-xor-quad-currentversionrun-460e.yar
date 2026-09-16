rule TTP_XOR_QUAD_CurrentVersionRun_460e {
  strings:
    $key_460e = { 15 61 [2] 31 6f [2] 1a 43 [2] 34 61 [2] 20 7a [2] 2f 60 [2] 31 7d [2] 33 7c [2] 28 7a [2] 34 7d [2] 28 52 }

  condition:
    any of them
}