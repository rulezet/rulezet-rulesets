rule TTP_XOR_QUAD_CurrentVersionRun_fd76 {
  strings:
    $key_fd76 = { ae 19 [2] 8a 17 [2] a1 3b [2] 8f 19 [2] 9b 02 [2] 94 18 [2] 8a 05 [2] 88 04 [2] 93 02 [2] 8f 05 [2] 93 2a }

  condition:
    any of them
}