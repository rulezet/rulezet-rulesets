rule TTP_XOR_QUAD_CurrentVersionRun_e2af {
  strings:
    $key_e2af = { b1 c0 [2] 95 ce [2] be e2 [2] 90 c0 [2] 84 db [2] 8b c1 [2] 95 dc [2] 97 dd [2] 8c db [2] 90 dc [2] 8c f3 }

  condition:
    any of them
}