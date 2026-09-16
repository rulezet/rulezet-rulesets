rule TTP_XOR_QUAD_CurrentVersionRun_089d {
  strings:
    $key_089d = { 5b f2 [2] 7f fc [2] 54 d0 [2] 7a f2 [2] 6e e9 [2] 61 f3 [2] 7f ee [2] 7d ef [2] 66 e9 [2] 7a ee [2] 66 c1 }

  condition:
    any of them
}