rule TTP_XOR_QUAD_CurrentVersionRun_7004 {
  strings:
    $key_7004 = { 23 6b [2] 07 65 [2] 2c 49 [2] 02 6b [2] 16 70 [2] 19 6a [2] 07 77 [2] 05 76 [2] 1e 70 [2] 02 77 [2] 1e 58 }

  condition:
    any of them
}