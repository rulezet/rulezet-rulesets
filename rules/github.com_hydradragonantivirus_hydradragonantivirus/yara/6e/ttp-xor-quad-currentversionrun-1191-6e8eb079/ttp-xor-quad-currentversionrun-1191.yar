rule TTP_XOR_QUAD_CurrentVersionRun_1191 {
  strings:
    $key_1191 = { 42 fe [2] 66 f0 [2] 4d dc [2] 63 fe [2] 77 e5 [2] 78 ff [2] 66 e2 [2] 64 e3 [2] 7f e5 [2] 63 e2 [2] 7f cd }

  condition:
    any of them
}