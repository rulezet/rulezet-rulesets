rule TTP_XOR_QUAD_CurrentVersionRun_fd31 {
  strings:
    $key_fd31 = { ae 5e [2] 8a 50 [2] a1 7c [2] 8f 5e [2] 9b 45 [2] 94 5f [2] 8a 42 [2] 88 43 [2] 93 45 [2] 8f 42 [2] 93 6d }

  condition:
    any of them
}