rule TTP_XOR_QUAD_CurrentVersionRun_4eed {
  strings:
    $key_4eed = { 1d 82 [2] 39 8c [2] 12 a0 [2] 3c 82 [2] 28 99 [2] 27 83 [2] 39 9e [2] 3b 9f [2] 20 99 [2] 3c 9e [2] 20 b1 }

  condition:
    any of them
}