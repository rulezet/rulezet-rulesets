rule TTP_XOR_QUAD_CurrentVersionRun_6bbb {
  strings:
    $key_6bbb = { 38 d4 [2] 1c da [2] 37 f6 [2] 19 d4 [2] 0d cf [2] 02 d5 [2] 1c c8 [2] 1e c9 [2] 05 cf [2] 19 c8 [2] 05 e7 }

  condition:
    any of them
}