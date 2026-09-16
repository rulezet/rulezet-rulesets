rule TTP_XOR_QUAD_CurrentVersionRun_299d {
  strings:
    $key_299d = { 7a f2 [2] 5e fc [2] 75 d0 [2] 5b f2 [2] 4f e9 [2] 40 f3 [2] 5e ee [2] 5c ef [2] 47 e9 [2] 5b ee [2] 47 c1 }

  condition:
    any of them
}