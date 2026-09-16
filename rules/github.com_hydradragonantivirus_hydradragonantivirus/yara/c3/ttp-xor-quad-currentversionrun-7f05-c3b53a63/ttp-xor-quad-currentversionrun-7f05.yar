rule TTP_XOR_QUAD_CurrentVersionRun_7f05 {
  strings:
    $key_7f05 = { 2c 6a [2] 08 64 [2] 23 48 [2] 0d 6a [2] 19 71 [2] 16 6b [2] 08 76 [2] 0a 77 [2] 11 71 [2] 0d 76 [2] 11 59 }

  condition:
    any of them
}