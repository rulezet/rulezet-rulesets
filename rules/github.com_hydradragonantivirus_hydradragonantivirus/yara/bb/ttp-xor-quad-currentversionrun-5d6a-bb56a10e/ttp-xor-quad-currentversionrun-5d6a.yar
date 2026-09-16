rule TTP_XOR_QUAD_CurrentVersionRun_5d6a {
  strings:
    $key_5d6a = { 0e 05 [2] 2a 0b [2] 01 27 [2] 2f 05 [2] 3b 1e [2] 34 04 [2] 2a 19 [2] 28 18 [2] 33 1e [2] 2f 19 [2] 33 36 }

  condition:
    any of them
}