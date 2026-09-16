rule TTP_XOR_QUAD_CurrentVersionRun_18ed {
  strings:
    $key_18ed = { 4b 82 [2] 6f 8c [2] 44 a0 [2] 6a 82 [2] 7e 99 [2] 71 83 [2] 6f 9e [2] 6d 9f [2] 76 99 [2] 6a 9e [2] 76 b1 }

  condition:
    any of them
}