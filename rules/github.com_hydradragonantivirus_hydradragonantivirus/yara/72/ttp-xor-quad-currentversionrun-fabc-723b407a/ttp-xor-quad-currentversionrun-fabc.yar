rule TTP_XOR_QUAD_CurrentVersionRun_fabc {
  strings:
    $key_fabc = { a9 d3 [2] 8d dd [2] a6 f1 [2] 88 d3 [2] 9c c8 [2] 93 d2 [2] 8d cf [2] 8f ce [2] 94 c8 [2] 88 cf [2] 94 e0 }

  condition:
    any of them
}