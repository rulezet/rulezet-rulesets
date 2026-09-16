rule TTP_XOR_QUAD_CurrentVersionRun_fd71 {
  strings:
    $key_fd71 = { ae 1e [2] 8a 10 [2] a1 3c [2] 8f 1e [2] 9b 05 [2] 94 1f [2] 8a 02 [2] 88 03 [2] 93 05 [2] 8f 02 [2] 93 2d }

  condition:
    any of them
}