rule TTP_XOR_QUAD_CurrentVersionRun_e2bf {
  strings:
    $key_e2bf = { b1 d0 [2] 95 de [2] be f2 [2] 90 d0 [2] 84 cb [2] 8b d1 [2] 95 cc [2] 97 cd [2] 8c cb [2] 90 cc [2] 8c e3 }

  condition:
    any of them
}