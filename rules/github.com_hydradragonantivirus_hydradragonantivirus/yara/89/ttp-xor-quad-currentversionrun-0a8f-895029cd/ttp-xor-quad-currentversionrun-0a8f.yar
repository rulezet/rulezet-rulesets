rule TTP_XOR_QUAD_CurrentVersionRun_0a8f {
  strings:
    $key_0a8f = { 59 e0 [2] 7d ee [2] 56 c2 [2] 78 e0 [2] 6c fb [2] 63 e1 [2] 7d fc [2] 7f fd [2] 64 fb [2] 78 fc [2] 64 d3 }

  condition:
    any of them
}