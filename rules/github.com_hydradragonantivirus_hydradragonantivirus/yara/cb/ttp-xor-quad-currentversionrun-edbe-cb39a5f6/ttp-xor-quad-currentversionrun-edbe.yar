rule TTP_XOR_QUAD_CurrentVersionRun_edbe {
  strings:
    $key_edbe = { be d1 [2] 9a df [2] b1 f3 [2] 9f d1 [2] 8b ca [2] 84 d0 [2] 9a cd [2] 98 cc [2] 83 ca [2] 9f cd [2] 83 e2 }

  condition:
    any of them
}