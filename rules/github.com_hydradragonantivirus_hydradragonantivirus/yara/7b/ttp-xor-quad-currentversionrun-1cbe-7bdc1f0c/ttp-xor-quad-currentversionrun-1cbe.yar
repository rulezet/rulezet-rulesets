rule TTP_XOR_QUAD_CurrentVersionRun_1cbe {
  strings:
    $key_1cbe = { 4f d1 [2] 6b df [2] 40 f3 [2] 6e d1 [2] 7a ca [2] 75 d0 [2] 6b cd [2] 69 cc [2] 72 ca [2] 6e cd [2] 72 e2 }

  condition:
    any of them
}