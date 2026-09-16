rule TTP_XOR_QUAD_CurrentVersionRun_3a65 {
  strings:
    $key_3a65 = { 69 0a [2] 4d 04 [2] 66 28 [2] 48 0a [2] 5c 11 [2] 53 0b [2] 4d 16 [2] 4f 17 [2] 54 11 [2] 48 16 [2] 54 39 }

  condition:
    any of them
}