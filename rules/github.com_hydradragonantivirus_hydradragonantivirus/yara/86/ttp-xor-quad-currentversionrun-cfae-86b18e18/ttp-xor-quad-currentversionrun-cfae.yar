rule TTP_XOR_QUAD_CurrentVersionRun_cfae {
  strings:
    $key_cfae = { 9c c1 [2] b8 cf [2] 93 e3 [2] bd c1 [2] a9 da [2] a6 c0 [2] b8 dd [2] ba dc [2] a1 da [2] bd dd [2] a1 f2 }

  condition:
    any of them
}