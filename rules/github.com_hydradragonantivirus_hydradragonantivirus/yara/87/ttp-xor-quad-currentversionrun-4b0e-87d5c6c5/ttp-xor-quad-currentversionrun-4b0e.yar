rule TTP_XOR_QUAD_CurrentVersionRun_4b0e {
  strings:
    $key_4b0e = { 18 61 [2] 3c 6f [2] 17 43 [2] 39 61 [2] 2d 7a [2] 22 60 [2] 3c 7d [2] 3e 7c [2] 25 7a [2] 39 7d [2] 25 52 }

  condition:
    any of them
}