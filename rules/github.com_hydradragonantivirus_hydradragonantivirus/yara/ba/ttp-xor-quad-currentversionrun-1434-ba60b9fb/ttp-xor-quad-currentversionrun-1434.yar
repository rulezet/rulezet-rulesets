rule TTP_XOR_QUAD_CurrentVersionRun_1434 {
  strings:
    $key_1434 = { 47 5b [2] 63 55 [2] 48 79 [2] 66 5b [2] 72 40 [2] 7d 5a [2] 63 47 [2] 61 46 [2] 7a 40 [2] 66 47 [2] 7a 68 }

  condition:
    any of them
}