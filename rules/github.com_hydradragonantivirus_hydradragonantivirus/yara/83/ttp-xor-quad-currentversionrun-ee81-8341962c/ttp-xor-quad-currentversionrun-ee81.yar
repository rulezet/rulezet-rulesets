rule TTP_XOR_QUAD_CurrentVersionRun_ee81 {
  strings:
    $key_ee81 = { bd ee [2] 99 e0 [2] b2 cc [2] 9c ee [2] 88 f5 [2] 87 ef [2] 99 f2 [2] 9b f3 [2] 80 f5 [2] 9c f2 [2] 80 dd }

  condition:
    any of them
}