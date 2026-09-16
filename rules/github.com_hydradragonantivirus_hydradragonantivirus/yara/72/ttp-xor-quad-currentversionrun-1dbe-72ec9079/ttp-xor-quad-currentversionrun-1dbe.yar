rule TTP_XOR_QUAD_CurrentVersionRun_1dbe {
  strings:
    $key_1dbe = { 4e d1 [2] 6a df [2] 41 f3 [2] 6f d1 [2] 7b ca [2] 74 d0 [2] 6a cd [2] 68 cc [2] 73 ca [2] 6f cd [2] 73 e2 }

  condition:
    any of them
}