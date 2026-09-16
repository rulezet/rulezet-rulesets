rule TTP_XOR_QUAD_CurrentVersionRun_1691 {
  strings:
    $key_1691 = { 45 fe [2] 61 f0 [2] 4a dc [2] 64 fe [2] 70 e5 [2] 7f ff [2] 61 e2 [2] 63 e3 [2] 78 e5 [2] 64 e2 [2] 78 cd }

  condition:
    any of them
}