rule TTP_XOR_QUAD_CurrentVersionRun_fece {
  strings:
    $key_fece = { ad a1 [2] 89 af [2] a2 83 [2] 8c a1 [2] 98 ba [2] 97 a0 [2] 89 bd [2] 8b bc [2] 90 ba [2] 8c bd [2] 90 92 }

  condition:
    any of them
}