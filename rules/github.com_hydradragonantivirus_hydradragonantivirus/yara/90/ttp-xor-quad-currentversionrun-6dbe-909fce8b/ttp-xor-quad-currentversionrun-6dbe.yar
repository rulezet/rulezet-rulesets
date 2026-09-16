rule TTP_XOR_QUAD_CurrentVersionRun_6dbe {
  strings:
    $key_6dbe = { 3e d1 [2] 1a df [2] 31 f3 [2] 1f d1 [2] 0b ca [2] 04 d0 [2] 1a cd [2] 18 cc [2] 03 ca [2] 1f cd [2] 03 e2 }

  condition:
    any of them
}