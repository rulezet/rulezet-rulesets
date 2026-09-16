rule TTP_XOR_QUAD_CurrentVersionRun_5de2 {
  strings:
    $key_5de2 = { 0e 8d [2] 2a 83 [2] 01 af [2] 2f 8d [2] 3b 96 [2] 34 8c [2] 2a 91 [2] 28 90 [2] 33 96 [2] 2f 91 [2] 33 be }

  condition:
    any of them
}