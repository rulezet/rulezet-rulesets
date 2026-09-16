rule TTP_XOR_QUAD_CurrentVersionRun_59ed {
  strings:
    $key_59ed = { 0a 82 [2] 2e 8c [2] 05 a0 [2] 2b 82 [2] 3f 99 [2] 30 83 [2] 2e 9e [2] 2c 9f [2] 37 99 [2] 2b 9e [2] 37 b1 }

  condition:
    any of them
}