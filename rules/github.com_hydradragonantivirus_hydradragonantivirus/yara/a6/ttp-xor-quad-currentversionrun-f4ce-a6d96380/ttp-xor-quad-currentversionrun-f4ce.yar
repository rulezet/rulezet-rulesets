rule TTP_XOR_QUAD_CurrentVersionRun_f4ce {
  strings:
    $key_f4ce = { a7 a1 [2] 83 af [2] a8 83 [2] 86 a1 [2] 92 ba [2] 9d a0 [2] 83 bd [2] 81 bc [2] 9a ba [2] 86 bd [2] 9a 92 }

  condition:
    any of them
}