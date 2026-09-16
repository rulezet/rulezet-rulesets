rule TTP_XOR_QUAD_CurrentVersionRun_e2bb {
  strings:
    $key_e2bb = { b1 d4 [2] 95 da [2] be f6 [2] 90 d4 [2] 84 cf [2] 8b d5 [2] 95 c8 [2] 97 c9 [2] 8c cf [2] 90 c8 [2] 8c e7 }

  condition:
    any of them
}