rule TTP_XOR_QUAD_CurrentVersionRun_10ce {
  strings:
    $key_10ce = { 43 a1 [2] 67 af [2] 4c 83 [2] 62 a1 [2] 76 ba [2] 79 a0 [2] 67 bd [2] 65 bc [2] 7e ba [2] 62 bd [2] 7e 92 }

  condition:
    any of them
}