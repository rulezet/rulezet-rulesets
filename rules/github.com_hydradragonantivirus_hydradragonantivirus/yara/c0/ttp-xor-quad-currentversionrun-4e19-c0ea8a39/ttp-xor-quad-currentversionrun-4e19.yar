rule TTP_XOR_QUAD_CurrentVersionRun_4e19 {
  strings:
    $key_4e19 = { 1d 76 [2] 39 78 [2] 12 54 [2] 3c 76 [2] 28 6d [2] 27 77 [2] 39 6a [2] 3b 6b [2] 20 6d [2] 3c 6a [2] 20 45 }

  condition:
    any of them
}