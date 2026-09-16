rule TTP_XOR_QUAD_CurrentVersionRun_fd0f {
  strings:
    $key_fd0f = { ae 60 [2] 8a 6e [2] a1 42 [2] 8f 60 [2] 9b 7b [2] 94 61 [2] 8a 7c [2] 88 7d [2] 93 7b [2] 8f 7c [2] 93 53 }

  condition:
    any of them
}