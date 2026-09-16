rule TTP_XOR_QUAD_CurrentVersionRun_1958 {
  strings:
    $key_1958 = { 4a 37 [2] 6e 39 [2] 45 15 [2] 6b 37 [2] 7f 2c [2] 70 36 [2] 6e 2b [2] 6c 2a [2] 77 2c [2] 6b 2b [2] 77 04 }

  condition:
    any of them
}