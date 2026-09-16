rule TTP_XOR_QUAD_CurrentVersionRun_fd81 {
  strings:
    $key_fd81 = { ae ee [2] 8a e0 [2] a1 cc [2] 8f ee [2] 9b f5 [2] 94 ef [2] 8a f2 [2] 88 f3 [2] 93 f5 [2] 8f f2 [2] 93 dd }

  condition:
    any of them
}