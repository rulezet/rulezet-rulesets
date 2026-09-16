rule TTP_XOR_QUAD_CurrentVersionRun_fd16 {
  strings:
    $key_fd16 = { ae 79 [2] 8a 77 [2] a1 5b [2] 8f 79 [2] 9b 62 [2] 94 78 [2] 8a 65 [2] 88 64 [2] 93 62 [2] 8f 65 [2] 93 4a }

  condition:
    any of them
}