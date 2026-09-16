rule TTP_XOR_QUAD_CurrentVersionRun_1bed {
  strings:
    $key_1bed = { 48 82 [2] 6c 8c [2] 47 a0 [2] 69 82 [2] 7d 99 [2] 72 83 [2] 6c 9e [2] 6e 9f [2] 75 99 [2] 69 9e [2] 75 b1 }

  condition:
    any of them
}