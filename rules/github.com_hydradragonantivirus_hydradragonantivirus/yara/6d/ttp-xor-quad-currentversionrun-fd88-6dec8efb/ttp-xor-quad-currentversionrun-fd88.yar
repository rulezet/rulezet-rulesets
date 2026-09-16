rule TTP_XOR_QUAD_CurrentVersionRun_fd88 {
  strings:
    $key_fd88 = { ae e7 [2] 8a e9 [2] a1 c5 [2] 8f e7 [2] 9b fc [2] 94 e6 [2] 8a fb [2] 88 fa [2] 93 fc [2] 8f fb [2] 93 d4 }

  condition:
    any of them
}