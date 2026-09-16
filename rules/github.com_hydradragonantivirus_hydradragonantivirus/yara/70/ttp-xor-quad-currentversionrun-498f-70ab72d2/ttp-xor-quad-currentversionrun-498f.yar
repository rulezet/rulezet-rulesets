rule TTP_XOR_QUAD_CurrentVersionRun_498f {
  strings:
    $key_498f = { 1a e0 [2] 3e ee [2] 15 c2 [2] 3b e0 [2] 2f fb [2] 20 e1 [2] 3e fc [2] 3c fd [2] 27 fb [2] 3b fc [2] 27 d3 }

  condition:
    any of them
}