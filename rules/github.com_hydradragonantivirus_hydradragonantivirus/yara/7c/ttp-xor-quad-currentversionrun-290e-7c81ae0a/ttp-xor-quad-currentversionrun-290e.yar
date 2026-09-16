rule TTP_XOR_QUAD_CurrentVersionRun_290e {
  strings:
    $key_290e = { 7a 61 [2] 5e 6f [2] 75 43 [2] 5b 61 [2] 4f 7a [2] 40 60 [2] 5e 7d [2] 5c 7c [2] 47 7a [2] 5b 7d [2] 47 52 }

  condition:
    any of them
}