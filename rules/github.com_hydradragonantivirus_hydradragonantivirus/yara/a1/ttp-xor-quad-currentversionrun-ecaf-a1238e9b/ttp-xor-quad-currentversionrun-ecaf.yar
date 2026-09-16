rule TTP_XOR_QUAD_CurrentVersionRun_ecaf {
  strings:
    $key_ecaf = { bf c0 [2] 9b ce [2] b0 e2 [2] 9e c0 [2] 8a db [2] 85 c1 [2] 9b dc [2] 99 dd [2] 82 db [2] 9e dc [2] 82 f3 }

  condition:
    any of them
}