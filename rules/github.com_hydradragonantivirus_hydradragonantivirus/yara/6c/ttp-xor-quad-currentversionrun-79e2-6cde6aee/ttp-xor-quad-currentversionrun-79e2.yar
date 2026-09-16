rule TTP_XOR_QUAD_CurrentVersionRun_79e2 {
  strings:
    $key_79e2 = { 2a 8d [2] 0e 83 [2] 25 af [2] 0b 8d [2] 1f 96 [2] 10 8c [2] 0e 91 [2] 0c 90 [2] 17 96 [2] 0b 91 [2] 17 be }

  condition:
    any of them
}