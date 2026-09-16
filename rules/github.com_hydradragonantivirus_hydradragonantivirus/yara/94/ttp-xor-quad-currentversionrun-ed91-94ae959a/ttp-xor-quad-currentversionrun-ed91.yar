rule TTP_XOR_QUAD_CurrentVersionRun_ed91 {
  strings:
    $key_ed91 = { be fe [2] 9a f0 [2] b1 dc [2] 9f fe [2] 8b e5 [2] 84 ff [2] 9a e2 [2] 98 e3 [2] 83 e5 [2] 9f e2 [2] 83 cd }

  condition:
    any of them
}