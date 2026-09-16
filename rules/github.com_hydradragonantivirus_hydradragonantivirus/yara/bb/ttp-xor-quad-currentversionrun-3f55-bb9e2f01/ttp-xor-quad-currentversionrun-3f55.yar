rule TTP_XOR_QUAD_CurrentVersionRun_3f55 {
  strings:
    $key_3f55 = { 6c 3a [2] 48 34 [2] 63 18 [2] 4d 3a [2] 59 21 [2] 56 3b [2] 48 26 [2] 4a 27 [2] 51 21 [2] 4d 26 [2] 51 09 }

  condition:
    any of them
}