rule TTP_XOR_QUAD_CurrentVersionRun_3a48 {
  strings:
    $key_3a48 = { 69 27 [2] 4d 29 [2] 66 05 [2] 48 27 [2] 5c 3c [2] 53 26 [2] 4d 3b [2] 4f 3a [2] 54 3c [2] 48 3b [2] 54 14 }

  condition:
    any of them
}