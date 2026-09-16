rule TTP_XOR_QUAD_CurrentVersionRun_698f {
  strings:
    $key_698f = { 3a e0 [2] 1e ee [2] 35 c2 [2] 1b e0 [2] 0f fb [2] 00 e1 [2] 1e fc [2] 1c fd [2] 07 fb [2] 1b fc [2] 07 d3 }

  condition:
    any of them
}