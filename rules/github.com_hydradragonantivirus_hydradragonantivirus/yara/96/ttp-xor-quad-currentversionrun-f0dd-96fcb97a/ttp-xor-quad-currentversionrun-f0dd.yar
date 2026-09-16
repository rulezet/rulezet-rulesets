rule TTP_XOR_QUAD_CurrentVersionRun_f0dd {
  strings:
    $key_f0dd = { a3 b2 [2] 87 bc [2] ac 90 [2] 82 b2 [2] 96 a9 [2] 99 b3 [2] 87 ae [2] 85 af [2] 9e a9 [2] 82 ae [2] 9e 81 }

  condition:
    any of them
}