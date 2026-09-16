rule TTP_XOR_QUAD_CurrentVersionRun_760e {
  strings:
    $key_760e = { 25 61 [2] 01 6f [2] 2a 43 [2] 04 61 [2] 10 7a [2] 1f 60 [2] 01 7d [2] 03 7c [2] 18 7a [2] 04 7d [2] 18 52 }

  condition:
    any of them
}