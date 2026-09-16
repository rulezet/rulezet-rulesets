rule TTP_XOR_QUAD_CurrentVersionRun_12af {
  strings:
    $key_12af = { 41 c0 [2] 65 ce [2] 4e e2 [2] 60 c0 [2] 74 db [2] 7b c1 [2] 65 dc [2] 67 dd [2] 7c db [2] 60 dc [2] 7c f3 }

  condition:
    any of them
}