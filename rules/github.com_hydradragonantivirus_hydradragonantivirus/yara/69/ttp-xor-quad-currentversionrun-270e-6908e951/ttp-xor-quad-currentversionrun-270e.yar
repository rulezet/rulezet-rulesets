rule TTP_XOR_QUAD_CurrentVersionRun_270e {
  strings:
    $key_270e = { 74 61 [2] 50 6f [2] 7b 43 [2] 55 61 [2] 41 7a [2] 4e 60 [2] 50 7d [2] 52 7c [2] 49 7a [2] 55 7d [2] 49 52 }

  condition:
    any of them
}