rule TTP_XOR_QUAD_CurrentVersionRun_28e2 {
  strings:
    $key_28e2 = { 7b 8d [2] 5f 83 [2] 74 af [2] 5a 8d [2] 4e 96 [2] 41 8c [2] 5f 91 [2] 5d 90 [2] 46 96 [2] 5a 91 [2] 46 be }

  condition:
    any of them
}