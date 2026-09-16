rule TTP_XOR_QUAD_CurrentVersionRun_fd02 {
  strings:
    $key_fd02 = { ae 6d [2] 8a 63 [2] a1 4f [2] 8f 6d [2] 9b 76 [2] 94 6c [2] 8a 71 [2] 88 70 [2] 93 76 [2] 8f 71 [2] 93 5e }

  condition:
    any of them
}