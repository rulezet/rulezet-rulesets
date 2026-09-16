rule TTP_XOR_QUAD_CurrentVersionRun_fd87 {
  strings:
    $key_fd87 = { ae e8 [2] 8a e6 [2] a1 ca [2] 8f e8 [2] 9b f3 [2] 94 e9 [2] 8a f4 [2] 88 f5 [2] 93 f3 [2] 8f f4 [2] 93 db }

  condition:
    any of them
}