rule TTP_XOR_QUAD_CurrentVersionRun_e5ce {
  strings:
    $key_e5ce = { b6 a1 [2] 92 af [2] b9 83 [2] 97 a1 [2] 83 ba [2] 8c a0 [2] 92 bd [2] 90 bc [2] 8b ba [2] 97 bd [2] 8b 92 }

  condition:
    any of them
}