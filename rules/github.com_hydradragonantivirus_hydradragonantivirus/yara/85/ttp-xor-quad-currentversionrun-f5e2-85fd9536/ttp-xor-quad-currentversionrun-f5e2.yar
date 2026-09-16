rule TTP_XOR_QUAD_CurrentVersionRun_f5e2 {
  strings:
    $key_f5e2 = { a6 8d [2] 82 83 [2] a9 af [2] 87 8d [2] 93 96 [2] 9c 8c [2] 82 91 [2] 80 90 [2] 9b 96 [2] 87 91 [2] 9b be }

  condition:
    any of them
}