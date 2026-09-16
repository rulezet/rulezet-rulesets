rule TTP_XOR_QUAD_CurrentVersionRun_4d3e {
  strings:
    $key_4d3e = { 1e 51 [2] 3a 5f [2] 11 73 [2] 3f 51 [2] 2b 4a [2] 24 50 [2] 3a 4d [2] 38 4c [2] 23 4a [2] 3f 4d [2] 23 62 }

  condition:
    any of them
}