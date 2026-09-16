rule TTP_XOR_QUAD_CurrentVersionRun_ebbb {
  strings:
    $key_ebbb = { b8 d4 [2] 9c da [2] b7 f6 [2] 99 d4 [2] 8d cf [2] 82 d5 [2] 9c c8 [2] 9e c9 [2] 85 cf [2] 99 c8 [2] 85 e7 }

  condition:
    any of them
}