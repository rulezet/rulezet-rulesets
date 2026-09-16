rule TTP_XOR_QUAD_CurrentVersionRun_33ce {
  strings:
    $key_33ce = { 60 a1 [2] 44 af [2] 6f 83 [2] 41 a1 [2] 55 ba [2] 5a a0 [2] 44 bd [2] 46 bc [2] 5d ba [2] 41 bd [2] 5d 92 }

  condition:
    any of them
}