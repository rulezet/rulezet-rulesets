rule TTP_XOR_QUAD_CurrentVersionRun_4dbe {
  strings:
    $key_4dbe = { 1e d1 [2] 3a df [2] 11 f3 [2] 3f d1 [2] 2b ca [2] 24 d0 [2] 3a cd [2] 38 cc [2] 23 ca [2] 3f cd [2] 23 e2 }

  condition:
    any of them
}