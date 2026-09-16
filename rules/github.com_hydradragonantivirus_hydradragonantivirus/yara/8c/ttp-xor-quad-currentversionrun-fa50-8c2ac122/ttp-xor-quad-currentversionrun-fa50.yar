rule TTP_XOR_QUAD_CurrentVersionRun_fa50 {
  strings:
    $key_fa50 = { a9 3f [2] 8d 31 [2] a6 1d [2] 88 3f [2] 9c 24 [2] 93 3e [2] 8d 23 [2] 8f 22 [2] 94 24 [2] 88 23 [2] 94 0c }

  condition:
    any of them
}