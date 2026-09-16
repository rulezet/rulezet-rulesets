rule TTP_XOR_QUAD_CurrentVersionRun_32ce {
  strings:
    $key_32ce = { 61 a1 [2] 45 af [2] 6e 83 [2] 40 a1 [2] 54 ba [2] 5b a0 [2] 45 bd [2] 47 bc [2] 5c ba [2] 40 bd [2] 5c 92 }

  condition:
    any of them
}