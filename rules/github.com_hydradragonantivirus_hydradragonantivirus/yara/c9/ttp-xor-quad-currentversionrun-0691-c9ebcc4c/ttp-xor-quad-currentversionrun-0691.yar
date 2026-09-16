rule TTP_XOR_QUAD_CurrentVersionRun_0691 {
  strings:
    $key_0691 = { 55 fe [2] 71 f0 [2] 5a dc [2] 74 fe [2] 60 e5 [2] 6f ff [2] 71 e2 [2] 73 e3 [2] 68 e5 [2] 74 e2 [2] 68 cd }

  condition:
    any of them
}