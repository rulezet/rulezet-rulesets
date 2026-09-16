rule TTP_XOR_QUAD_CurrentVersionRun_eece {
  strings:
    $key_eece = { bd a1 [2] 99 af [2] b2 83 [2] 9c a1 [2] 88 ba [2] 87 a0 [2] 99 bd [2] 9b bc [2] 80 ba [2] 9c bd [2] 80 92 }

  condition:
    any of them
}