rule TTP_XOR_QUAD_CurrentVersionRun_fd11 {
  strings:
    $key_fd11 = { ae 7e [2] 8a 70 [2] a1 5c [2] 8f 7e [2] 9b 65 [2] 94 7f [2] 8a 62 [2] 88 63 [2] 93 65 [2] 8f 62 [2] 93 4d }

  condition:
    any of them
}