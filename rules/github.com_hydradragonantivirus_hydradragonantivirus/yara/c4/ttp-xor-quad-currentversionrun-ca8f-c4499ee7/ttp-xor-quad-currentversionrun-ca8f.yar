rule TTP_XOR_QUAD_CurrentVersionRun_ca8f {
  strings:
    $key_ca8f = { 99 e0 [2] bd ee [2] 96 c2 [2] b8 e0 [2] ac fb [2] a3 e1 [2] bd fc [2] bf fd [2] a4 fb [2] b8 fc [2] a4 d3 }

  condition:
    any of them
}