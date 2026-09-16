rule TTP_XOR_QUAD_CurrentVersionRun_6ced {
  strings:
    $key_6ced = { 3f 82 [2] 1b 8c [2] 30 a0 [2] 1e 82 [2] 0a 99 [2] 05 83 [2] 1b 9e [2] 19 9f [2] 02 99 [2] 1e 9e [2] 02 b1 }

  condition:
    any of them
}