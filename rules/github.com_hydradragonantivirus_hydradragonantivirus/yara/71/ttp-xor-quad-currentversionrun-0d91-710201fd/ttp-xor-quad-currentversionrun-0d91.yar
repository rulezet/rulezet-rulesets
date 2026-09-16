rule TTP_XOR_QUAD_CurrentVersionRun_0d91 {
  strings:
    $key_0d91 = { 5e fe [2] 7a f0 [2] 51 dc [2] 7f fe [2] 6b e5 [2] 64 ff [2] 7a e2 [2] 78 e3 [2] 63 e5 [2] 7f e2 [2] 63 cd }

  condition:
    any of them
}