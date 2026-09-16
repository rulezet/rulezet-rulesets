rule TTP_XOR_QUAD_CurrentVersionRun_fa0b {
  strings:
    $key_fa0b = { a9 64 [2] 8d 6a [2] a6 46 [2] 88 64 [2] 9c 7f [2] 93 65 [2] 8d 78 [2] 8f 79 [2] 94 7f [2] 88 78 [2] 94 57 }

  condition:
    any of them
}