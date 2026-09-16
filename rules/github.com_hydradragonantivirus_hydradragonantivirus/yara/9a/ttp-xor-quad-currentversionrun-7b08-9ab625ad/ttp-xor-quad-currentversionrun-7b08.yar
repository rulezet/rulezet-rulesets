rule TTP_XOR_QUAD_CurrentVersionRun_7b08 {
  strings:
    $key_7b08 = { 28 67 [2] 0c 69 [2] 27 45 [2] 09 67 [2] 1d 7c [2] 12 66 [2] 0c 7b [2] 0e 7a [2] 15 7c [2] 09 7b [2] 15 54 }

  condition:
    any of them
}