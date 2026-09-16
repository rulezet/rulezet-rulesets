rule TTP_XOR_QUAD_CurrentVersionRun_5933 {
  strings:
    $key_5933 = { 0a 5c [2] 2e 52 [2] 05 7e [2] 2b 5c [2] 3f 47 [2] 30 5d [2] 2e 40 [2] 2c 41 [2] 37 47 [2] 2b 40 [2] 37 6f }

  condition:
    any of them
}