rule TTP_XOR_QUAD_CurrentVersionRun_f7f1 {
  strings:
    $key_f7f1 = { a4 9e [2] 80 90 [2] ab bc [2] 85 9e [2] 91 85 [2] 9e 9f [2] 80 82 [2] 82 83 [2] 99 85 [2] 85 82 [2] 99 ad }

  condition:
    any of them
}