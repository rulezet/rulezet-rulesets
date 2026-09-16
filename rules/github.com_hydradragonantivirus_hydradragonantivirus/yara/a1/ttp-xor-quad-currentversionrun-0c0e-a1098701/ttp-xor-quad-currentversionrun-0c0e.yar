rule TTP_XOR_QUAD_CurrentVersionRun_0c0e {
  strings:
    $key_0c0e = { 5f 61 [2] 7b 6f [2] 50 43 [2] 7e 61 [2] 6a 7a [2] 65 60 [2] 7b 7d [2] 79 7c [2] 62 7a [2] 7e 7d [2] 62 52 }

  condition:
    any of them
}