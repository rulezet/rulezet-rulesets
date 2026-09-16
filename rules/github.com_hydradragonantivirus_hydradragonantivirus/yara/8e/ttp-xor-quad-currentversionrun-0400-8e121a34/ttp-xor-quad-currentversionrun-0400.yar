rule TTP_XOR_QUAD_CurrentVersionRun_0400 {
  strings:
    $key_0400 = { 57 6f [2] 73 61 [2] 58 4d [2] 76 6f [2] 62 74 [2] 6d 6e [2] 73 73 [2] 71 72 [2] 6a 74 [2] 76 73 [2] 6a 5c }

  condition:
    any of them
}