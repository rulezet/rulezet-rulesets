rule TTP_XOR_QUAD_CurrentVersionRun_1f20 {
  strings:
    $key_1f20 = { 4c 4f [2] 68 41 [2] 43 6d [2] 6d 4f [2] 79 54 [2] 76 4e [2] 68 53 [2] 6a 52 [2] 71 54 [2] 6d 53 [2] 71 7c }

  condition:
    any of them
}