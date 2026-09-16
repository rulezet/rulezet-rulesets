rule TTP_XOR_QUAD_CurrentVersionRun_e2ba {
  strings:
    $key_e2ba = { b1 d5 [2] 95 db [2] be f7 [2] 90 d5 [2] 84 ce [2] 8b d4 [2] 95 c9 [2] 97 c8 [2] 8c ce [2] 90 c9 [2] 8c e6 }

  condition:
    any of them
}