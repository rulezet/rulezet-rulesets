rule TTP_XOR_QUAD_CurrentVersionRun_e2ce {
  strings:
    $key_e2ce = { b1 a1 [2] 95 af [2] be 83 [2] 90 a1 [2] 84 ba [2] 8b a0 [2] 95 bd [2] 97 bc [2] 8c ba [2] 90 bd [2] 8c 92 }

  condition:
    any of them
}