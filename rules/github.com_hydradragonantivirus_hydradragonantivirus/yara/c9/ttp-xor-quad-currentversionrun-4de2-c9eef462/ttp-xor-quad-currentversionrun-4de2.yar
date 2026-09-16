rule TTP_XOR_QUAD_CurrentVersionRun_4de2 {
  strings:
    $key_4de2 = { 1e 8d [2] 3a 83 [2] 11 af [2] 3f 8d [2] 2b 96 [2] 24 8c [2] 3a 91 [2] 38 90 [2] 23 96 [2] 3f 91 [2] 23 be }

  condition:
    any of them
}