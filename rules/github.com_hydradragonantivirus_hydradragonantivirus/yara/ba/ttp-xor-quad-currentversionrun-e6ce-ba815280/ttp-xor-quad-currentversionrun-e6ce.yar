rule TTP_XOR_QUAD_CurrentVersionRun_e6ce {
  strings:
    $key_e6ce = { b5 a1 [2] 91 af [2] ba 83 [2] 94 a1 [2] 80 ba [2] 8f a0 [2] 91 bd [2] 93 bc [2] 88 ba [2] 94 bd [2] 88 92 }

  condition:
    any of them
}