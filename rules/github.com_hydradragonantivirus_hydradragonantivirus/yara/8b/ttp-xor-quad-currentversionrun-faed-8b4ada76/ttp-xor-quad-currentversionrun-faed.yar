rule TTP_XOR_QUAD_CurrentVersionRun_faed {
  strings:
    $key_faed = { a9 82 [2] 8d 8c [2] a6 a0 [2] 88 82 [2] 9c 99 [2] 93 83 [2] 8d 9e [2] 8f 9f [2] 94 99 [2] 88 9e [2] 94 b1 }

  condition:
    any of them
}