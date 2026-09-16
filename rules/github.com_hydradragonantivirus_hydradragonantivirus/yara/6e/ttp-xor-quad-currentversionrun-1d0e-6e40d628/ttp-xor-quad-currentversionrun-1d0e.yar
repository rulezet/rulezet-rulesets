rule TTP_XOR_QUAD_CurrentVersionRun_1d0e {
  strings:
    $key_1d0e = { 4e 61 [2] 6a 6f [2] 41 43 [2] 6f 61 [2] 7b 7a [2] 74 60 [2] 6a 7d [2] 68 7c [2] 73 7a [2] 6f 7d [2] 73 52 }

  condition:
    any of them
}