rule TTP_XOR_QUAD_CurrentVersionRun_1ce2 {
  strings:
    $key_1ce2 = { 4f 8d [2] 6b 83 [2] 40 af [2] 6e 8d [2] 7a 96 [2] 75 8c [2] 6b 91 [2] 69 90 [2] 72 96 [2] 6e 91 [2] 72 be }

  condition:
    any of them
}