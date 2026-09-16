rule TTP_XOR_QUAD_CurrentVersionRun_e99d {
  strings:
    $key_e99d = { ba f2 [2] 9e fc [2] b5 d0 [2] 9b f2 [2] 8f e9 [2] 80 f3 [2] 9e ee [2] 9c ef [2] 87 e9 [2] 9b ee [2] 87 c1 }

  condition:
    any of them
}