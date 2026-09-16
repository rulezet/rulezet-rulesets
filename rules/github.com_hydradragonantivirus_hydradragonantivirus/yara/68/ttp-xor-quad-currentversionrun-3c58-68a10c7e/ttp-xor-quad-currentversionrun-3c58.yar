rule TTP_XOR_QUAD_CurrentVersionRun_3c58 {
  strings:
    $key_3c58 = { 6f 37 [2] 4b 39 [2] 60 15 [2] 4e 37 [2] 5a 2c [2] 55 36 [2] 4b 2b [2] 49 2a [2] 52 2c [2] 4e 2b [2] 52 04 }

  condition:
    any of them
}