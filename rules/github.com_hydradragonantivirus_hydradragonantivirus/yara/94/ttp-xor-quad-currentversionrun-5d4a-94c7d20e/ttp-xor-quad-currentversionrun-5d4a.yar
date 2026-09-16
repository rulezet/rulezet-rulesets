rule TTP_XOR_QUAD_CurrentVersionRun_5d4a {
  strings:
    $key_5d4a = { 0e 25 [2] 2a 2b [2] 01 07 [2] 2f 25 [2] 3b 3e [2] 34 24 [2] 2a 39 [2] 28 38 [2] 33 3e [2] 2f 39 [2] 33 16 }

  condition:
    any of them
}