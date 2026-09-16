rule TTP_XOR_QUAD_CurrentVersionRun_ed97 {
  strings:
    $key_ed97 = { be f8 [2] 9a f6 [2] b1 da [2] 9f f8 [2] 8b e3 [2] 84 f9 [2] 9a e4 [2] 98 e5 [2] 83 e3 [2] 9f e4 [2] 83 cb }

  condition:
    any of them
}