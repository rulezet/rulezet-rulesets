rule TTP_XOR_QUAD_CurrentVersionRun_599d {
  strings:
    $key_599d = { 0a f2 [2] 2e fc [2] 05 d0 [2] 2b f2 [2] 3f e9 [2] 30 f3 [2] 2e ee [2] 2c ef [2] 37 e9 [2] 2b ee [2] 37 c1 }

  condition:
    any of them
}