rule TTP_XOR_QUAD_CurrentVersionRun_fa23 {
  strings:
    $key_fa23 = { a9 4c [2] 8d 42 [2] a6 6e [2] 88 4c [2] 9c 57 [2] 93 4d [2] 8d 50 [2] 8f 51 [2] 94 57 [2] 88 50 [2] 94 7f }

  condition:
    any of them
}