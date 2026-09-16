rule TTP_XOR_QUAD_CurrentVersionRun_17ed {
  strings:
    $key_17ed = { 44 82 [2] 60 8c [2] 4b a0 [2] 65 82 [2] 71 99 [2] 7e 83 [2] 60 9e [2] 62 9f [2] 79 99 [2] 65 9e [2] 79 b1 }

  condition:
    any of them
}