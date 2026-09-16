rule TTP_XOR_QUAD_CurrentVersionRun_099d {
  strings:
    $key_099d = { 5a f2 [2] 7e fc [2] 55 d0 [2] 7b f2 [2] 6f e9 [2] 60 f3 [2] 7e ee [2] 7c ef [2] 67 e9 [2] 7b ee [2] 67 c1 }

  condition:
    any of them
}