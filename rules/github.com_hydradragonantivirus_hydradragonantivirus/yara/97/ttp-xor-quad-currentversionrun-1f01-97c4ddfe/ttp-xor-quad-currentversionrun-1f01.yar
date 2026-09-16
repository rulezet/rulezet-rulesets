rule TTP_XOR_QUAD_CurrentVersionRun_1f01 {
  strings:
    $key_1f01 = { 4c 6e [2] 68 60 [2] 43 4c [2] 6d 6e [2] 79 75 [2] 76 6f [2] 68 72 [2] 6a 73 [2] 71 75 [2] 6d 72 [2] 71 5d }

  condition:
    any of them
}