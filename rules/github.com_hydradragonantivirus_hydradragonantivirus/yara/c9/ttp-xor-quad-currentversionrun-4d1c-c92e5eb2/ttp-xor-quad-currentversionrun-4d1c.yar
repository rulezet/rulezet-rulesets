rule TTP_XOR_QUAD_CurrentVersionRun_4d1c {
  strings:
    $key_4d1c = { 1e 73 [2] 3a 7d [2] 11 51 [2] 3f 73 [2] 2b 68 [2] 24 72 [2] 3a 6f [2] 38 6e [2] 23 68 [2] 3f 6f [2] 23 40 }

  condition:
    any of them
}