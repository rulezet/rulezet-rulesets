rule TTP_XOR_QUAD_CurrentVersionRun_1abc {
  strings:
    $key_1abc = { 49 d3 [2] 6d dd [2] 46 f1 [2] 68 d3 [2] 7c c8 [2] 73 d2 [2] 6d cf [2] 6f ce [2] 74 c8 [2] 68 cf [2] 74 e0 }

  condition:
    any of them
}