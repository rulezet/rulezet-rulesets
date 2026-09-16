rule TTP_XOR_QUAD_CurrentVersionRun_1429 {
  strings:
    $key_1429 = { 47 46 [2] 63 48 [2] 48 64 [2] 66 46 [2] 72 5d [2] 7d 47 [2] 63 5a [2] 61 5b [2] 7a 5d [2] 66 5a [2] 7a 75 }

  condition:
    any of them
}