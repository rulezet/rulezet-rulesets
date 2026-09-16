rule TTP_XOR_QUAD_CurrentVersionRun_0090 {
  strings:
    $key_0090 = { 53 ff [2] 77 f1 [2] 5c dd [2] 72 ff [2] 66 e4 [2] 69 fe [2] 77 e3 [2] 75 e2 [2] 6e e4 [2] 72 e3 [2] 6e cc }

  condition:
    any of them
}