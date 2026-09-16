rule TTP_XOR_QUAD_CurrentVersionRun_0cbe {
  strings:
    $key_0cbe = { 5f d1 [2] 7b df [2] 50 f3 [2] 7e d1 [2] 6a ca [2] 65 d0 [2] 7b cd [2] 79 cc [2] 62 ca [2] 7e cd [2] 62 e2 }

  condition:
    any of them
}