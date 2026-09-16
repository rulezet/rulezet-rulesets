rule TTP_XOR_QUAD_CurrentVersionRun_0bbb {
  strings:
    $key_0bbb = { 58 d4 [2] 7c da [2] 57 f6 [2] 79 d4 [2] 6d cf [2] 62 d5 [2] 7c c8 [2] 7e c9 [2] 65 cf [2] 79 c8 [2] 65 e7 }

  condition:
    any of them
}