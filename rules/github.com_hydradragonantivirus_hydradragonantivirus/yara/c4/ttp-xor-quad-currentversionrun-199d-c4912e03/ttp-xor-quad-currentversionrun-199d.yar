rule TTP_XOR_QUAD_CurrentVersionRun_199d {
  strings:
    $key_199d = { 4a f2 [2] 6e fc [2] 45 d0 [2] 6b f2 [2] 7f e9 [2] 70 f3 [2] 6e ee [2] 6c ef [2] 77 e9 [2] 6b ee [2] 77 c1 }

  condition:
    any of them
}