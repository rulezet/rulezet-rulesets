rule TTP_XOR_QUAD_CurrentVersionRun_3464 {
  strings:
    $key_3464 = { 67 0b [2] 43 05 [2] 68 29 [2] 46 0b [2] 52 10 [2] 5d 0a [2] 43 17 [2] 41 16 [2] 5a 10 [2] 46 17 [2] 5a 38 }

  condition:
    any of them
}