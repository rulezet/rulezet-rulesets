rule TTP_XOR_QUAD_CurrentVersionRun_eb8c {
  strings:
    $key_eb8c = { b8 e3 [2] 9c ed [2] b7 c1 [2] 99 e3 [2] 8d f8 [2] 82 e2 [2] 9c ff [2] 9e fe [2] 85 f8 [2] 99 ff [2] 85 d0 }

  condition:
    any of them
}