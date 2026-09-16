rule TTP_XOR_QUAD_CurrentVersionRun_01ed {
  strings:
    $key_01ed = { 52 82 [2] 76 8c [2] 5d a0 [2] 73 82 [2] 67 99 [2] 68 83 [2] 76 9e [2] 74 9f [2] 6f 99 [2] 73 9e [2] 6f b1 }

  condition:
    any of them
}