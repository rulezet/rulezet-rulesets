rule TTP_XOR_QUAD_CurrentVersionRun_3f8f {
  strings:
    $key_3f8f = { 6c e0 [2] 48 ee [2] 63 c2 [2] 4d e0 [2] 59 fb [2] 56 e1 [2] 48 fc [2] 4a fd [2] 51 fb [2] 4d fc [2] 51 d3 }

  condition:
    any of them
}