rule TTP_XOR_QUAD_CurrentVersionRun_4d3c {
  strings:
    $key_4d3c = { 1e 53 [2] 3a 5d [2] 11 71 [2] 3f 53 [2] 2b 48 [2] 24 52 [2] 3a 4f [2] 38 4e [2] 23 48 [2] 3f 4f [2] 23 60 }

  condition:
    any of them
}