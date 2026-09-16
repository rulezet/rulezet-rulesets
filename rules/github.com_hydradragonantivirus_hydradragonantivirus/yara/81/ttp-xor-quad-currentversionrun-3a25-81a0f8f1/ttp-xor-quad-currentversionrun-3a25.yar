rule TTP_XOR_QUAD_CurrentVersionRun_3a25 {
  strings:
    $key_3a25 = { 69 4a [2] 4d 44 [2] 66 68 [2] 48 4a [2] 5c 51 [2] 53 4b [2] 4d 56 [2] 4f 57 [2] 54 51 [2] 48 56 [2] 54 79 }

  condition:
    any of them
}