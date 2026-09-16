rule TTP_XOR_QUAD_CurrentVersionRun_faea {
  strings:
    $key_faea = { a9 85 [2] 8d 8b [2] a6 a7 [2] 88 85 [2] 9c 9e [2] 93 84 [2] 8d 99 [2] 8f 98 [2] 94 9e [2] 88 99 [2] 94 b6 }

  condition:
    any of them
}