rule TTP_XOR_QUAD_CurrentVersionRun_07e2 {
  strings:
    $key_07e2 = { 54 8d [2] 70 83 [2] 5b af [2] 75 8d [2] 61 96 [2] 6e 8c [2] 70 91 [2] 72 90 [2] 69 96 [2] 75 91 [2] 69 be }

  condition:
    any of them
}