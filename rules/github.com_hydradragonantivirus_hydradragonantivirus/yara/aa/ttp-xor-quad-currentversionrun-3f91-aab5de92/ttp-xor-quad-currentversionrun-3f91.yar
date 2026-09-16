rule TTP_XOR_QUAD_CurrentVersionRun_3f91 {
  strings:
    $key_3f91 = { 6c fe [2] 48 f0 [2] 63 dc [2] 4d fe [2] 59 e5 [2] 56 ff [2] 48 e2 [2] 4a e3 [2] 51 e5 [2] 4d e2 [2] 51 cd }

  condition:
    any of them
}