rule TTP_XOR_QUAD_CurrentVersionRun_6abc {
  strings:
    $key_6abc = { 39 d3 [2] 1d dd [2] 36 f1 [2] 18 d3 [2] 0c c8 [2] 03 d2 [2] 1d cf [2] 1f ce [2] 04 c8 [2] 18 cf [2] 04 e0 }

  condition:
    any of them
}