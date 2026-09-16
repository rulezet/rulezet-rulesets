rule TTP_XOR_QUAD_CurrentVersionRun_430e {
  strings:
    $key_430e = { 10 61 [2] 34 6f [2] 1f 43 [2] 31 61 [2] 25 7a [2] 2a 60 [2] 34 7d [2] 36 7c [2] 2d 7a [2] 31 7d [2] 2d 52 }

  condition:
    any of them
}