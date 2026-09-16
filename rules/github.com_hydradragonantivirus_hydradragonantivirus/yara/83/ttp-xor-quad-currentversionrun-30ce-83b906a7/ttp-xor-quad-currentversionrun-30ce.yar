rule TTP_XOR_QUAD_CurrentVersionRun_30ce {
  strings:
    $key_30ce = { 63 a1 [2] 47 af [2] 6c 83 [2] 42 a1 [2] 56 ba [2] 59 a0 [2] 47 bd [2] 45 bc [2] 5e ba [2] 42 bd [2] 5e 92 }

  condition:
    any of them
}