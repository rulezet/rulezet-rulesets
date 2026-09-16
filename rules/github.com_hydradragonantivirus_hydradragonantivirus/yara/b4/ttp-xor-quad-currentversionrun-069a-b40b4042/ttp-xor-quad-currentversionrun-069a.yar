rule TTP_XOR_QUAD_CurrentVersionRun_069a {
  strings:
    $key_069a = { 55 f5 [2] 71 fb [2] 5a d7 [2] 74 f5 [2] 60 ee [2] 6f f4 [2] 71 e9 [2] 73 e8 [2] 68 ee [2] 74 e9 [2] 68 c6 }

  condition:
    any of them
}