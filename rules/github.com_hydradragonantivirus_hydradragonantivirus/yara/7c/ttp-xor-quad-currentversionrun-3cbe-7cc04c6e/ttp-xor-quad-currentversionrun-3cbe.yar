rule TTP_XOR_QUAD_CurrentVersionRun_3cbe {
  strings:
    $key_3cbe = { 6f d1 [2] 4b df [2] 60 f3 [2] 4e d1 [2] 5a ca [2] 55 d0 [2] 4b cd [2] 49 cc [2] 52 ca [2] 4e cd [2] 52 e2 }

  condition:
    any of them
}