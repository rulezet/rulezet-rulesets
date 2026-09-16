rule TTP_XOR_QUAD_CurrentVersionRun_6808 {
  strings:
    $key_6808 = { 3b 67 [2] 1f 69 [2] 34 45 [2] 1a 67 [2] 0e 7c [2] 01 66 [2] 1f 7b [2] 1d 7a [2] 06 7c [2] 1a 7b [2] 06 54 }

  condition:
    any of them
}