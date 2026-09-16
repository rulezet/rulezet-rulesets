rule TTP_XOR_QUAD_CurrentVersionRun_5705 {
  strings:
    $key_5705 = { 04 6a [2] 20 64 [2] 0b 48 [2] 25 6a [2] 31 71 [2] 3e 6b [2] 20 76 [2] 22 77 [2] 39 71 [2] 25 76 [2] 39 59 }

  condition:
    any of them
}