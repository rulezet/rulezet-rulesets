rule TTP_XOR_QUAD_CurrentVersionRun_3090 {
  strings:
    $key_3090 = { 63 ff [2] 47 f1 [2] 6c dd [2] 42 ff [2] 56 e4 [2] 59 fe [2] 47 e3 [2] 45 e2 [2] 5e e4 [2] 42 e3 [2] 5e cc }

  condition:
    any of them
}