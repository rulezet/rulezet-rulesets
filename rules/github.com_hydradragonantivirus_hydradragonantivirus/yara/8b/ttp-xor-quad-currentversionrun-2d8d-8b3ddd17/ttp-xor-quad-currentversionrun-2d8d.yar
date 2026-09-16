rule TTP_XOR_QUAD_CurrentVersionRun_2d8d {
  strings:
    $key_2d8d = { 7e e2 [2] 5a ec [2] 71 c0 [2] 5f e2 [2] 4b f9 [2] 44 e3 [2] 5a fe [2] 58 ff [2] 43 f9 [2] 5f fe [2] 43 d1 }

  condition:
    any of them
}