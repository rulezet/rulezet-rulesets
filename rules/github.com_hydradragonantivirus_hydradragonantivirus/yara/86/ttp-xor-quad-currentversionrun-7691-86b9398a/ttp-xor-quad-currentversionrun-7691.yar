rule TTP_XOR_QUAD_CurrentVersionRun_7691 {
  strings:
    $key_7691 = { 25 fe [2] 01 f0 [2] 2a dc [2] 04 fe [2] 10 e5 [2] 1f ff [2] 01 e2 [2] 03 e3 [2] 18 e5 [2] 04 e2 [2] 18 cd }

  condition:
    any of them
}