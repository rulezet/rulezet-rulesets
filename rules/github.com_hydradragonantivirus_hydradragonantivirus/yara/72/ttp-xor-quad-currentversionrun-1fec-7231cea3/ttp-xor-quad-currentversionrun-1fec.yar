rule TTP_XOR_QUAD_CurrentVersionRun_1fec {
  strings:
    $key_1fec = { 4c 83 [2] 68 8d [2] 43 a1 [2] 6d 83 [2] 79 98 [2] 76 82 [2] 68 9f [2] 6a 9e [2] 71 98 [2] 6d 9f [2] 71 b0 }

  condition:
    any of them
}