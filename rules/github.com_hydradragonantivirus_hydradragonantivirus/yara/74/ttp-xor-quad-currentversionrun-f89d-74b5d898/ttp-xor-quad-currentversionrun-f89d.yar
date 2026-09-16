rule TTP_XOR_QUAD_CurrentVersionRun_f89d {
  strings:
    $key_f89d = { ab f2 [2] 8f fc [2] a4 d0 [2] 8a f2 [2] 9e e9 [2] 91 f3 [2] 8f ee [2] 8d ef [2] 96 e9 [2] 8a ee [2] 96 c1 }

  condition:
    any of them
}