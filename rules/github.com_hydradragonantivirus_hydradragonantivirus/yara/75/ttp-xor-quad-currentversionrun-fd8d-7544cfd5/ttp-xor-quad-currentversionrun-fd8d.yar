rule TTP_XOR_QUAD_CurrentVersionRun_fd8d {
  strings:
    $key_fd8d = { ae e2 [2] 8a ec [2] a1 c0 [2] 8f e2 [2] 9b f9 [2] 94 e3 [2] 8a fe [2] 88 ff [2] 93 f9 [2] 8f fe [2] 93 d1 }

  condition:
    any of them
}