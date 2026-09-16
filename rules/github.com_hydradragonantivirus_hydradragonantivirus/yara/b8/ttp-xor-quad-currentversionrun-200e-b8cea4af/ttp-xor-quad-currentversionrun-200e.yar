rule TTP_XOR_QUAD_CurrentVersionRun_200e {
  strings:
    $key_200e = { 73 61 [2] 57 6f [2] 7c 43 [2] 52 61 [2] 46 7a [2] 49 60 [2] 57 7d [2] 55 7c [2] 4e 7a [2] 52 7d [2] 4e 52 }

  condition:
    any of them
}