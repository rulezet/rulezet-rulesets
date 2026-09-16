rule TTP_XOR_QUAD_CurrentVersionRun_37ed {
  strings:
    $key_37ed = { 64 82 [2] 40 8c [2] 6b a0 [2] 45 82 [2] 51 99 [2] 5e 83 [2] 40 9e [2] 42 9f [2] 59 99 [2] 45 9e [2] 59 b1 }

  condition:
    any of them
}