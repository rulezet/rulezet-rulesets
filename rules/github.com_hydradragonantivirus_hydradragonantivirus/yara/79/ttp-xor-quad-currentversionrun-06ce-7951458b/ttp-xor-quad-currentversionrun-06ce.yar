rule TTP_XOR_QUAD_CurrentVersionRun_06ce {
  strings:
    $key_06ce = { 55 a1 [2] 71 af [2] 5a 83 [2] 74 a1 [2] 60 ba [2] 6f a0 [2] 71 bd [2] 73 bc [2] 68 ba [2] 74 bd [2] 68 92 }

  condition:
    any of them
}