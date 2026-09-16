rule TTP_XOR_QUAD_CurrentVersionRun_7708 {
  strings:
    $key_7708 = { 24 67 [2] 00 69 [2] 2b 45 [2] 05 67 [2] 11 7c [2] 1e 66 [2] 00 7b [2] 02 7a [2] 19 7c [2] 05 7b [2] 19 54 }

  condition:
    any of them
}