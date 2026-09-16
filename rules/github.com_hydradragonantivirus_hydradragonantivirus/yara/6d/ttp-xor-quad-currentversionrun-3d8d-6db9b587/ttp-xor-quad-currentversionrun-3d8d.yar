rule TTP_XOR_QUAD_CurrentVersionRun_3d8d {
  strings:
    $key_3d8d = { 6e e2 [2] 4a ec [2] 61 c0 [2] 4f e2 [2] 5b f9 [2] 54 e3 [2] 4a fe [2] 48 ff [2] 53 f9 [2] 4f fe [2] 53 d1 }

  condition:
    any of them
}