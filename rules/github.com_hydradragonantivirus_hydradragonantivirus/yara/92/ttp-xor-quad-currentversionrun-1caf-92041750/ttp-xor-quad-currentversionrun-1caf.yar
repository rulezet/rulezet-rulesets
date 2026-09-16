rule TTP_XOR_QUAD_CurrentVersionRun_1caf {
  strings:
    $key_1caf = { 4f c0 [2] 6b ce [2] 40 e2 [2] 6e c0 [2] 7a db [2] 75 c1 [2] 6b dc [2] 69 dd [2] 72 db [2] 6e dc [2] 72 f3 }

  condition:
    any of them
}