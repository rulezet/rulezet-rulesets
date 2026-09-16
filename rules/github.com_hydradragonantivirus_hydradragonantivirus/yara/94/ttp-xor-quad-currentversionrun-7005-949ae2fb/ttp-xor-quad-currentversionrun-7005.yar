rule TTP_XOR_QUAD_CurrentVersionRun_7005 {
  strings:
    $key_7005 = { 23 6a [2] 07 64 [2] 2c 48 [2] 02 6a [2] 16 71 [2] 19 6b [2] 07 76 [2] 05 77 [2] 1e 71 [2] 02 76 [2] 1e 59 }

  condition:
    any of them
}