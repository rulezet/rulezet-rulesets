rule TTP_XOR_QUAD_CurrentVersionRun_0a90 {
  strings:
    $key_0a90 = { 59 ff [2] 7d f1 [2] 56 dd [2] 78 ff [2] 6c e4 [2] 63 fe [2] 7d e3 [2] 7f e2 [2] 64 e4 [2] 78 e3 [2] 64 cc }

  condition:
    any of them
}