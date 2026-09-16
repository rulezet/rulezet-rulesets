rule TTP_XOR_QUAD_CurrentVersionRun_6008 {
  strings:
    $key_6008 = { 33 67 [2] 17 69 [2] 3c 45 [2] 12 67 [2] 06 7c [2] 09 66 [2] 17 7b [2] 15 7a [2] 0e 7c [2] 12 7b [2] 0e 54 }

  condition:
    any of them
}