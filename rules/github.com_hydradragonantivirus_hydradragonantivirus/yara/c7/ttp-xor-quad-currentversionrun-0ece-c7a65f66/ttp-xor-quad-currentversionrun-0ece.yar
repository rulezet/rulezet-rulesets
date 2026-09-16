rule TTP_XOR_QUAD_CurrentVersionRun_0ece {
  strings:
    $key_0ece = { 5d a1 [2] 79 af [2] 52 83 [2] 7c a1 [2] 68 ba [2] 67 a0 [2] 79 bd [2] 7b bc [2] 60 ba [2] 7c bd [2] 60 92 }

  condition:
    any of them
}