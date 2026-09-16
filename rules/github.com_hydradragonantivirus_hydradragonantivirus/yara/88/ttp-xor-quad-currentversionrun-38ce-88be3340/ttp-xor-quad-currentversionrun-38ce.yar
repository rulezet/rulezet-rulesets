rule TTP_XOR_QUAD_CurrentVersionRun_38ce {
  strings:
    $key_38ce = { 6b a1 [2] 4f af [2] 64 83 [2] 4a a1 [2] 5e ba [2] 51 a0 [2] 4f bd [2] 4d bc [2] 56 ba [2] 4a bd [2] 56 92 }

  condition:
    any of them
}