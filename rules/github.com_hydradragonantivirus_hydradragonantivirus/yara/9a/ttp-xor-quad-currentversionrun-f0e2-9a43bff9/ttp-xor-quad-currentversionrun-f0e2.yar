rule TTP_XOR_QUAD_CurrentVersionRun_f0e2 {
  strings:
    $key_f0e2 = { a3 8d [2] 87 83 [2] ac af [2] 82 8d [2] 96 96 [2] 99 8c [2] 87 91 [2] 85 90 [2] 9e 96 [2] 82 91 [2] 9e be }

  condition:
    any of them
}