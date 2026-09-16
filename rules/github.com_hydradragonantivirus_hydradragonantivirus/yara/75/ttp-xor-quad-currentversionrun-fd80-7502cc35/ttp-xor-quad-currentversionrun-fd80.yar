rule TTP_XOR_QUAD_CurrentVersionRun_fd80 {
  strings:
    $key_fd80 = { ae ef [2] 8a e1 [2] a1 cd [2] 8f ef [2] 9b f4 [2] 94 ee [2] 8a f3 [2] 88 f2 [2] 93 f4 [2] 8f f3 [2] 93 dc }

  condition:
    any of them
}