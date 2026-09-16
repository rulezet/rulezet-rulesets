rule TTP_XOR_QUAD_CurrentVersionRun_0abc {
  strings:
    $key_0abc = { 59 d3 [2] 7d dd [2] 56 f1 [2] 78 d3 [2] 6c c8 [2] 63 d2 [2] 7d cf [2] 7f ce [2] 64 c8 [2] 78 cf [2] 64 e0 }

  condition:
    any of them
}