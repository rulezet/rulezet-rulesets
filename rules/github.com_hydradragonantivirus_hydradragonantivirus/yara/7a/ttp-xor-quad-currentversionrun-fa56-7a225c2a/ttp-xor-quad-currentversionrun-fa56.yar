rule TTP_XOR_QUAD_CurrentVersionRun_fa56 {
  strings:
    $key_fa56 = { a9 39 [2] 8d 37 [2] a6 1b [2] 88 39 [2] 9c 22 [2] 93 38 [2] 8d 25 [2] 8f 24 [2] 94 22 [2] 88 25 [2] 94 0a }

  condition:
    any of them
}