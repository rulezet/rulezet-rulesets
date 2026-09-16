rule TTP_XOR_QUAD_CurrentVersionRun_31ce {
  strings:
    $key_31ce = { 62 a1 [2] 46 af [2] 6d 83 [2] 43 a1 [2] 57 ba [2] 58 a0 [2] 46 bd [2] 44 bc [2] 5f ba [2] 43 bd [2] 5f 92 }

  condition:
    any of them
}