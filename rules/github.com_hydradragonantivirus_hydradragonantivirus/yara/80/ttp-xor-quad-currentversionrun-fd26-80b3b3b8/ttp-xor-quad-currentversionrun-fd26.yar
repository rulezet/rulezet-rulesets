rule TTP_XOR_QUAD_CurrentVersionRun_fd26 {
  strings:
    $key_fd26 = { ae 49 [2] 8a 47 [2] a1 6b [2] 8f 49 [2] 9b 52 [2] 94 48 [2] 8a 55 [2] 88 54 [2] 93 52 [2] 8f 55 [2] 93 7a }

  condition:
    any of them
}