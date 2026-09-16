rule TTP_XOR_QUAD_CurrentVersionRun_ed96 {
  strings:
    $key_ed96 = { be f9 [2] 9a f7 [2] b1 db [2] 9f f9 [2] 8b e2 [2] 84 f8 [2] 9a e5 [2] 98 e4 [2] 83 e2 [2] 9f e5 [2] 83 ca }

  condition:
    any of them
}