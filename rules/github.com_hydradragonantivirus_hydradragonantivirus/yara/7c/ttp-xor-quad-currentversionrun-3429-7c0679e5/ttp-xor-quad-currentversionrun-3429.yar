rule TTP_XOR_QUAD_CurrentVersionRun_3429 {
  strings:
    $key_3429 = { 67 46 [2] 43 48 [2] 68 64 [2] 46 46 [2] 52 5d [2] 5d 47 [2] 43 5a [2] 41 5b [2] 5a 5d [2] 46 5a [2] 5a 75 }

  condition:
    any of them
}