rule TTP_XOR_QUAD_CurrentVersionRun_2c8f {
  strings:
    $key_2c8f = { 7f e0 [2] 5b ee [2] 70 c2 [2] 5e e0 [2] 4a fb [2] 45 e1 [2] 5b fc [2] 59 fd [2] 42 fb [2] 5e fc [2] 42 d3 }

  condition:
    any of them
}