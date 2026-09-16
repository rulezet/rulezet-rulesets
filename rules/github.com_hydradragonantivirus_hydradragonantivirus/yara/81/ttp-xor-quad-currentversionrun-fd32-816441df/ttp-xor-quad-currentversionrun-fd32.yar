rule TTP_XOR_QUAD_CurrentVersionRun_fd32 {
  strings:
    $key_fd32 = { ae 5d [2] 8a 53 [2] a1 7f [2] 8f 5d [2] 9b 46 [2] 94 5c [2] 8a 41 [2] 88 40 [2] 93 46 [2] 8f 41 [2] 93 6e }

  condition:
    any of them
}