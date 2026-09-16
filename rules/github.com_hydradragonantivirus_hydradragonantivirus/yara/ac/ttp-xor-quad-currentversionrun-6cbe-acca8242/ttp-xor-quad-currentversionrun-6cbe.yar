rule TTP_XOR_QUAD_CurrentVersionRun_6cbe {
  strings:
    $key_6cbe = { 3f d1 [2] 1b df [2] 30 f3 [2] 1e d1 [2] 0a ca [2] 05 d0 [2] 1b cd [2] 19 cc [2] 02 ca [2] 1e cd [2] 02 e2 }

  condition:
    any of them
}