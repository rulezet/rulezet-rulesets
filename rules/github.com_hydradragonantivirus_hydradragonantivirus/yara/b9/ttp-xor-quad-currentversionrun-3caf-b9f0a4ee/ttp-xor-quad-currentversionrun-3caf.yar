rule TTP_XOR_QUAD_CurrentVersionRun_3caf {
  strings:
    $key_3caf = { 6f c0 [2] 4b ce [2] 60 e2 [2] 4e c0 [2] 5a db [2] 55 c1 [2] 4b dc [2] 49 dd [2] 52 db [2] 4e dc [2] 52 f3 }

  condition:
    any of them
}