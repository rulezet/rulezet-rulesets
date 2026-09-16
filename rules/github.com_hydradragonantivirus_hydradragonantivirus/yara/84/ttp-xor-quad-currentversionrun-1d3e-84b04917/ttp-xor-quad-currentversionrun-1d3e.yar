rule TTP_XOR_QUAD_CurrentVersionRun_1d3e {
  strings:
    $key_1d3e = { 4e 51 [2] 6a 5f [2] 41 73 [2] 6f 51 [2] 7b 4a [2] 74 50 [2] 6a 4d [2] 68 4c [2] 73 4a [2] 6f 4d [2] 73 62 }

  condition:
    any of them
}