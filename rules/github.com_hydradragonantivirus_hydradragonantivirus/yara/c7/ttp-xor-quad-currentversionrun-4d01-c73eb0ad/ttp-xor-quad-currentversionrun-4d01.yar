rule TTP_XOR_QUAD_CurrentVersionRun_4d01 {
  strings:
    $key_4d01 = { 1e 6e [2] 3a 60 [2] 11 4c [2] 3f 6e [2] 2b 75 [2] 24 6f [2] 3a 72 [2] 38 73 [2] 23 75 [2] 3f 72 [2] 23 5d }

  condition:
    any of them
}