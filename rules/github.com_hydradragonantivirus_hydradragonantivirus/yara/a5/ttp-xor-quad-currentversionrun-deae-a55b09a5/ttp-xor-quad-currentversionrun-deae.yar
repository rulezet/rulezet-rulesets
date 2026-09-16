rule TTP_XOR_QUAD_CurrentVersionRun_deae {
  strings:
    $key_deae = { 8d c1 [2] a9 cf [2] 82 e3 [2] ac c1 [2] b8 da [2] b7 c0 [2] a9 dd [2] ab dc [2] b0 da [2] ac dd [2] b0 f2 }

  condition:
    any of them
}