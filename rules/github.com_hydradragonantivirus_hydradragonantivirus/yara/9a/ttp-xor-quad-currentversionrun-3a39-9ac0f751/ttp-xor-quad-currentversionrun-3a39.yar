rule TTP_XOR_QUAD_CurrentVersionRun_3a39 {
  strings:
    $key_3a39 = { 69 56 [2] 4d 58 [2] 66 74 [2] 48 56 [2] 5c 4d [2] 53 57 [2] 4d 4a [2] 4f 4b [2] 54 4d [2] 48 4a [2] 54 65 }

  condition:
    any of them
}