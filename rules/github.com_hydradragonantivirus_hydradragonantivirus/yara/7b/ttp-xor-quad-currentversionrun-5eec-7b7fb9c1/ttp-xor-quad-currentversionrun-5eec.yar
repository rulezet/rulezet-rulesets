rule TTP_XOR_QUAD_CurrentVersionRun_5eec {
  strings:
    $key_5eec = { 0d 83 [2] 29 8d [2] 02 a1 [2] 2c 83 [2] 38 98 [2] 37 82 [2] 29 9f [2] 2b 9e [2] 30 98 [2] 2c 9f [2] 30 b0 }

  condition:
    any of them
}