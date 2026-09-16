rule TTP_XOR_QUAD_CurrentVersionRun_1f00 {
  strings:
    $key_1f00 = { 4c 6f [2] 68 61 [2] 43 4d [2] 6d 6f [2] 79 74 [2] 76 6e [2] 68 73 [2] 6a 72 [2] 71 74 [2] 6d 73 [2] 71 5c }

  condition:
    any of them
}