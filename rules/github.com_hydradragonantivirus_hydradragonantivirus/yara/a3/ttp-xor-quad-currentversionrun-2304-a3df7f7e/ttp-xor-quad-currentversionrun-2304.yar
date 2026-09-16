rule TTP_XOR_QUAD_CurrentVersionRun_2304 {
  strings:
    $key_2304 = { 70 6b [2] 54 65 [2] 7f 49 [2] 51 6b [2] 45 70 [2] 4a 6a [2] 54 77 [2] 56 76 [2] 4d 70 [2] 51 77 [2] 4d 58 }

  condition:
    any of them
}