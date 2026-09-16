rule TTP_XOR_QUAD_CurrentVersionRun_c58f {
  strings:
    $key_c58f = { 96 e0 [2] b2 ee [2] 99 c2 [2] b7 e0 [2] a3 fb [2] ac e1 [2] b2 fc [2] b0 fd [2] ab fb [2] b7 fc [2] ab d3 }

  condition:
    any of them
}