rule TTP_XOR_QUAD_CurrentVersionRun_2315 {
  strings:
    $key_2315 = { 70 7a [2] 54 74 [2] 7f 58 [2] 51 7a [2] 45 61 [2] 4a 7b [2] 54 66 [2] 56 67 [2] 4d 61 [2] 51 66 [2] 4d 49 }

  condition:
    any of them
}