rule TTP_XOR_QUAD_CurrentVersionRun_080e {
  strings:
    $key_080e = { 5b 61 [2] 7f 6f [2] 54 43 [2] 7a 61 [2] 6e 7a [2] 61 60 [2] 7f 7d [2] 7d 7c [2] 66 7a [2] 7a 7d [2] 66 52 }

  condition:
    any of them
}