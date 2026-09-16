rule TTP_XOR_QUAD_CurrentVersionRun_bb8f {
  strings:
    $key_bb8f = { e8 e0 [2] cc ee [2] e7 c2 [2] c9 e0 [2] dd fb [2] d2 e1 [2] cc fc [2] ce fd [2] d5 fb [2] c9 fc [2] d5 d3 }

  condition:
    any of them
}