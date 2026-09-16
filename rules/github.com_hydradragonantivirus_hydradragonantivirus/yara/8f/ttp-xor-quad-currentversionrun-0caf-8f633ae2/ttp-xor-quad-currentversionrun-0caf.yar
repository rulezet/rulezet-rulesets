rule TTP_XOR_QUAD_CurrentVersionRun_0caf {
  strings:
    $key_0caf = { 5f c0 [2] 7b ce [2] 50 e2 [2] 7e c0 [2] 6a db [2] 65 c1 [2] 7b dc [2] 79 dd [2] 62 db [2] 7e dc [2] 62 f3 }

  condition:
    any of them
}