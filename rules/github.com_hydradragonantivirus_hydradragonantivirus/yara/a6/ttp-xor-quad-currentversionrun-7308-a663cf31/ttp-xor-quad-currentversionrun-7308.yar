rule TTP_XOR_QUAD_CurrentVersionRun_7308 {
  strings:
    $key_7308 = { 20 67 [2] 04 69 [2] 2f 45 [2] 01 67 [2] 15 7c [2] 1a 66 [2] 04 7b [2] 06 7a [2] 1d 7c [2] 01 7b [2] 1d 54 }

  condition:
    any of them
}