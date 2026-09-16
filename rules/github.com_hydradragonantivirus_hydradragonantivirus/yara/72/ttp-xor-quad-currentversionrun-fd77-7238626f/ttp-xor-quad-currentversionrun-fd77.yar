rule TTP_XOR_QUAD_CurrentVersionRun_fd77 {
  strings:
    $key_fd77 = { ae 18 [2] 8a 16 [2] a1 3a [2] 8f 18 [2] 9b 03 [2] 94 19 [2] 8a 04 [2] 88 05 [2] 93 03 [2] 8f 04 [2] 93 2b }

  condition:
    any of them
}