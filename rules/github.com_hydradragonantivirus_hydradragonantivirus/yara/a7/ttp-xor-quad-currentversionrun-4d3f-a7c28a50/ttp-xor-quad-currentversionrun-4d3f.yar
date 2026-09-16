rule TTP_XOR_QUAD_CurrentVersionRun_4d3f {
  strings:
    $key_4d3f = { 1e 50 [2] 3a 5e [2] 11 72 [2] 3f 50 [2] 2b 4b [2] 24 51 [2] 3a 4c [2] 38 4d [2] 23 4b [2] 3f 4c [2] 23 63 }

  condition:
    any of them
}