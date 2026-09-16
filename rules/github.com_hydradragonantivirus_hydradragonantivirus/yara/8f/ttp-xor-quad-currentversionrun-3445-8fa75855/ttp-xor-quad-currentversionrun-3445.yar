rule TTP_XOR_QUAD_CurrentVersionRun_3445 {
  strings:
    $key_3445 = { 67 2a [2] 43 24 [2] 68 08 [2] 46 2a [2] 52 31 [2] 5d 2b [2] 43 36 [2] 41 37 [2] 5a 31 [2] 46 36 [2] 5a 19 }

  condition:
    any of them
}