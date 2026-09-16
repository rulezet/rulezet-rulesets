rule TTP_XOR_QUAD_CurrentVersionRun_22ce {
  strings:
    $key_22ce = { 71 a1 [2] 55 af [2] 7e 83 [2] 50 a1 [2] 44 ba [2] 4b a0 [2] 55 bd [2] 57 bc [2] 4c ba [2] 50 bd [2] 4c 92 }

  condition:
    any of them
}