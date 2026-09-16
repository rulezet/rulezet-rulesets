rule TTP_XOR_QUAD_CurrentVersionRun_5d26 {
  strings:
    $key_5d26 = { 0e 49 [2] 2a 47 [2] 01 6b [2] 2f 49 [2] 3b 52 [2] 34 48 [2] 2a 55 [2] 28 54 [2] 33 52 [2] 2f 55 [2] 33 7a }

  condition:
    any of them
}