rule TTP_XOR_QUAD_CurrentVersionRun_fd01 {
  strings:
    $key_fd01 = { ae 6e [2] 8a 60 [2] a1 4c [2] 8f 6e [2] 9b 75 [2] 94 6f [2] 8a 72 [2] 88 73 [2] 93 75 [2] 8f 72 [2] 93 5d }

  condition:
    any of them
}