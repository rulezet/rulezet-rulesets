rule TTP_XOR_QUAD_CurrentVersionRun_21ce {
  strings:
    $key_21ce = { 72 a1 [2] 56 af [2] 7d 83 [2] 53 a1 [2] 47 ba [2] 48 a0 [2] 56 bd [2] 54 bc [2] 4f ba [2] 53 bd [2] 4f 92 }

  condition:
    any of them
}