rule TTP_XOR_QUAD_CurrentVersionRun_5962 {
  strings:
    $key_5962 = { 0a 0d [2] 2e 03 [2] 05 2f [2] 2b 0d [2] 3f 16 [2] 30 0c [2] 2e 11 [2] 2c 10 [2] 37 16 [2] 2b 11 [2] 37 3e }

  condition:
    any of them
}