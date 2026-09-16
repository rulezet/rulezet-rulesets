rule TTP_XOR_QUAD_CurrentVersionRun_24ce {
  strings:
    $key_24ce = { 77 a1 [2] 53 af [2] 78 83 [2] 56 a1 [2] 42 ba [2] 4d a0 [2] 53 bd [2] 51 bc [2] 4a ba [2] 56 bd [2] 4a 92 }

  condition:
    any of them
}