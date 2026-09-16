rule TTP_XOR_QUAD_CurrentVersionRun_fd0a {
  strings:
    $key_fd0a = { ae 65 [2] 8a 6b [2] a1 47 [2] 8f 65 [2] 9b 7e [2] 94 64 [2] 8a 79 [2] 88 78 [2] 93 7e [2] 8f 79 [2] 93 56 }

  condition:
    any of them
}