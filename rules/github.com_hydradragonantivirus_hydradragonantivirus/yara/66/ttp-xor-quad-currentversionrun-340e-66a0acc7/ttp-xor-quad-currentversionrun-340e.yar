rule TTP_XOR_QUAD_CurrentVersionRun_340e {
  strings:
    $key_340e = { 67 61 [2] 43 6f [2] 68 43 [2] 46 61 [2] 52 7a [2] 5d 60 [2] 43 7d [2] 41 7c [2] 5a 7a [2] 46 7d [2] 5a 52 }

  condition:
    any of them
}