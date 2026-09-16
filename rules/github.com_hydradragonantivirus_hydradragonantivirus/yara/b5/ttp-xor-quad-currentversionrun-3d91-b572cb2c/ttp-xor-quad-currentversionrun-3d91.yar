rule TTP_XOR_QUAD_CurrentVersionRun_3d91 {
  strings:
    $key_3d91 = { 6e fe [2] 4a f0 [2] 61 dc [2] 4f fe [2] 5b e5 [2] 54 ff [2] 4a e2 [2] 48 e3 [2] 53 e5 [2] 4f e2 [2] 53 cd }

  condition:
    any of them
}