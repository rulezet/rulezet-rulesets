rule TTP_XOR_QUAD_CurrentVersionRun_2691 {
  strings:
    $key_2691 = { 75 fe [2] 51 f0 [2] 7a dc [2] 54 fe [2] 40 e5 [2] 4f ff [2] 51 e2 [2] 53 e3 [2] 48 e5 [2] 54 e2 [2] 48 cd }

  condition:
    any of them
}