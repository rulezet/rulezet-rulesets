rule TTP_XOR_QUAD_CurrentVersionRun_60c0 {
  strings:
    $key_60c0 = { 33 af [2] 17 a1 [2] 3c 8d [2] 12 af [2] 06 b4 [2] 09 ae [2] 17 b3 [2] 15 b2 [2] 0e b4 [2] 12 b3 [2] 0e 9c }

  condition:
    any of them
}