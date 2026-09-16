rule TTP_XOR_QUAD_CurrentVersionRun_0590 {
  strings:
    $key_0590 = { 56 ff [2] 72 f1 [2] 59 dd [2] 77 ff [2] 63 e4 [2] 6c fe [2] 72 e3 [2] 70 e2 [2] 6b e4 [2] 77 e3 [2] 6b cc }

  condition:
    any of them
}