rule TTP_XOR_QUAD_CurrentVersionRun_7605 {
  strings:
    $key_7605 = { 25 6a [2] 01 64 [2] 2a 48 [2] 04 6a [2] 10 71 [2] 1f 6b [2] 01 76 [2] 03 77 [2] 18 71 [2] 04 76 [2] 18 59 }

  condition:
    any of them
}