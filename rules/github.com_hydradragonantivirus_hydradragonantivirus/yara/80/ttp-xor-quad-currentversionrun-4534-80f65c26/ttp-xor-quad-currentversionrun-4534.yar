rule TTP_XOR_QUAD_CurrentVersionRun_4534 {
  strings:
    $key_4534 = { 16 5b [2] 32 55 [2] 19 79 [2] 37 5b [2] 23 40 [2] 2c 5a [2] 32 47 [2] 30 46 [2] 2b 40 [2] 37 47 [2] 2b 68 }

  condition:
    any of them
}