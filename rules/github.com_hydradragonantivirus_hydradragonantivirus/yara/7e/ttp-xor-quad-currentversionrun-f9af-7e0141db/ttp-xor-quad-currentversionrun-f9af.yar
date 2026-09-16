rule TTP_XOR_QUAD_CurrentVersionRun_f9af {
  strings:
    $key_f9af = { aa c0 [2] 8e ce [2] a5 e2 [2] 8b c0 [2] 9f db [2] 90 c1 [2] 8e dc [2] 8c dd [2] 97 db [2] 8b dc [2] 97 f3 }

  condition:
    any of them
}