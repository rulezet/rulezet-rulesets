rule TTP_XOR_QUAD_CurrentVersionRun_e9af {
  strings:
    $key_e9af = { ba c0 [2] 9e ce [2] b5 e2 [2] 9b c0 [2] 8f db [2] 80 c1 [2] 9e dc [2] 9c dd [2] 87 db [2] 9b dc [2] 87 f3 }

  condition:
    any of them
}