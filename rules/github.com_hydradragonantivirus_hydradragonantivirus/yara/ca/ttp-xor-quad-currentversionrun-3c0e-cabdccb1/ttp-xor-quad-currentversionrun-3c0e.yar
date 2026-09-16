rule TTP_XOR_QUAD_CurrentVersionRun_3c0e {
  strings:
    $key_3c0e = { 6f 61 [2] 4b 6f [2] 60 43 [2] 4e 61 [2] 5a 7a [2] 55 60 [2] 4b 7d [2] 49 7c [2] 52 7a [2] 4e 7d [2] 52 52 }

  condition:
    any of them
}