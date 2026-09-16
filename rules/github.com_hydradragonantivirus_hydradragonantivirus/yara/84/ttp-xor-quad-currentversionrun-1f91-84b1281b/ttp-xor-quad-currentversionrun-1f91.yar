rule TTP_XOR_QUAD_CurrentVersionRun_1f91 {
  strings:
    $key_1f91 = { 4c fe [2] 68 f0 [2] 43 dc [2] 6d fe [2] 79 e5 [2] 76 ff [2] 68 e2 [2] 6a e3 [2] 71 e5 [2] 6d e2 [2] 71 cd }

  condition:
    any of them
}