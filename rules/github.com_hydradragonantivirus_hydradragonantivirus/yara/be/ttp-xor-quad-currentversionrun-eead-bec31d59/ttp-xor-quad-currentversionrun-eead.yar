rule TTP_XOR_QUAD_CurrentVersionRun_eead {
  strings:
    $key_eead = { bd c2 [2] 99 cc [2] b2 e0 [2] 9c c2 [2] 88 d9 [2] 87 c3 [2] 99 de [2] 9b df [2] 80 d9 [2] 9c de [2] 80 f1 }

  condition:
    any of them
}