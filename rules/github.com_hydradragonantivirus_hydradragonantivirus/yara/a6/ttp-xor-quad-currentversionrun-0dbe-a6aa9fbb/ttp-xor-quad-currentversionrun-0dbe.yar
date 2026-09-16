rule TTP_XOR_QUAD_CurrentVersionRun_0dbe {
  strings:
    $key_0dbe = { 5e d1 [2] 7a df [2] 51 f3 [2] 7f d1 [2] 6b ca [2] 64 d0 [2] 7a cd [2] 78 cc [2] 63 ca [2] 7f cd [2] 63 e2 }

  condition:
    any of them
}