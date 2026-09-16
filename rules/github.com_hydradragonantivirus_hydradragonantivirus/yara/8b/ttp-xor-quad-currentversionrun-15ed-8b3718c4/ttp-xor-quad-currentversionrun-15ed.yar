rule TTP_XOR_QUAD_CurrentVersionRun_15ed {
  strings:
    $key_15ed = { 46 82 [2] 62 8c [2] 49 a0 [2] 67 82 [2] 73 99 [2] 7c 83 [2] 62 9e [2] 60 9f [2] 7b 99 [2] 67 9e [2] 7b b1 }

  condition:
    any of them
}