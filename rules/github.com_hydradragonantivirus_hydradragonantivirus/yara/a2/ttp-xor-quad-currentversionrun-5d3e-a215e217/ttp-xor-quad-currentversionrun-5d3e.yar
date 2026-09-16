rule TTP_XOR_QUAD_CurrentVersionRun_5d3e {
  strings:
    $key_5d3e = { 0e 51 [2] 2a 5f [2] 01 73 [2] 2f 51 [2] 3b 4a [2] 34 50 [2] 2a 4d [2] 28 4c [2] 33 4a [2] 2f 4d [2] 33 62 }

  condition:
    any of them
}