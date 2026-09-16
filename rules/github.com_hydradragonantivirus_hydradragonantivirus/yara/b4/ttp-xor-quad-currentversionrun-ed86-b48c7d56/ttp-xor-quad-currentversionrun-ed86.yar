rule TTP_XOR_QUAD_CurrentVersionRun_ed86 {
  strings:
    $key_ed86 = { be e9 [2] 9a e7 [2] b1 cb [2] 9f e9 [2] 8b f2 [2] 84 e8 [2] 9a f5 [2] 98 f4 [2] 83 f2 [2] 9f f5 [2] 83 da }

  condition:
    any of them
}