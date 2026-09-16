rule TTP_XOR_QUAD_CurrentVersionRun_0bec {
  strings:
    $key_0bec = { 58 83 [2] 7c 8d [2] 57 a1 [2] 79 83 [2] 6d 98 [2] 62 82 [2] 7c 9f [2] 7e 9e [2] 65 98 [2] 79 9f [2] 65 b0 }

  condition:
    any of them
}