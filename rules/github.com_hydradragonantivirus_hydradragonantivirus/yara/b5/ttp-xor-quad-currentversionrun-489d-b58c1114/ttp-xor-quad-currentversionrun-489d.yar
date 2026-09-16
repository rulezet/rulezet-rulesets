rule TTP_XOR_QUAD_CurrentVersionRun_489d {
  strings:
    $key_489d = { 1b f2 [2] 3f fc [2] 14 d0 [2] 3a f2 [2] 2e e9 [2] 21 f3 [2] 3f ee [2] 3d ef [2] 26 e9 [2] 3a ee [2] 26 c1 }

  condition:
    any of them
}