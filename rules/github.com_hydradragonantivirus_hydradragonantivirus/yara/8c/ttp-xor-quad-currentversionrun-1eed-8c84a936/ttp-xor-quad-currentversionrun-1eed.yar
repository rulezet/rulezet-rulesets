rule TTP_XOR_QUAD_CurrentVersionRun_1eed {
  strings:
    $key_1eed = { 4d 82 [2] 69 8c [2] 42 a0 [2] 6c 82 [2] 78 99 [2] 77 83 [2] 69 9e [2] 6b 9f [2] 70 99 [2] 6c 9e [2] 70 b1 }

  condition:
    any of them
}