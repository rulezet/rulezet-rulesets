rule TTP_XOR_QUAD_CurrentVersionRun_2f91 {
  strings:
    $key_2f91 = { 7c fe [2] 58 f0 [2] 73 dc [2] 5d fe [2] 49 e5 [2] 46 ff [2] 58 e2 [2] 5a e3 [2] 41 e5 [2] 5d e2 [2] 41 cd }

  condition:
    any of them
}