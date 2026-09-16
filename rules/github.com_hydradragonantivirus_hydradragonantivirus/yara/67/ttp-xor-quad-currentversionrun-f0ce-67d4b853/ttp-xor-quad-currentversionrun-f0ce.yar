rule TTP_XOR_QUAD_CurrentVersionRun_f0ce {
  strings:
    $key_f0ce = { a3 a1 [2] 87 af [2] ac 83 [2] 82 a1 [2] 96 ba [2] 99 a0 [2] 87 bd [2] 85 bc [2] 9e ba [2] 82 bd [2] 9e 92 }

  condition:
    any of them
}