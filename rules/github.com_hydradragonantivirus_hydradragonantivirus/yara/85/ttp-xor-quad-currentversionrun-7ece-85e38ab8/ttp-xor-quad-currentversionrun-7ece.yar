rule TTP_XOR_QUAD_CurrentVersionRun_7ece {
  strings:
    $key_7ece = { 2d a1 [2] 09 af [2] 22 83 [2] 0c a1 [2] 18 ba [2] 17 a0 [2] 09 bd [2] 0b bc [2] 10 ba [2] 0c bd [2] 10 92 }

  condition:
    any of them
}