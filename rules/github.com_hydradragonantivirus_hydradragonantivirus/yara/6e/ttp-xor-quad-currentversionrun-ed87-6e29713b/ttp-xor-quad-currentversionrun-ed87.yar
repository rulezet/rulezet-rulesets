rule TTP_XOR_QUAD_CurrentVersionRun_ed87 {
  strings:
    $key_ed87 = { be e8 [2] 9a e6 [2] b1 ca [2] 9f e8 [2] 8b f3 [2] 84 e9 [2] 9a f4 [2] 98 f5 [2] 83 f3 [2] 9f f4 [2] 83 db }

  condition:
    any of them
}