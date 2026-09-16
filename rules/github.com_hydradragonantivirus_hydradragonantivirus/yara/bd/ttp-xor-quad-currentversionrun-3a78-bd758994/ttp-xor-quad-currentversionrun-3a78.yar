rule TTP_XOR_QUAD_CurrentVersionRun_3a78 {
  strings:
    $key_3a78 = { 69 17 [2] 4d 19 [2] 66 35 [2] 48 17 [2] 5c 0c [2] 53 16 [2] 4d 0b [2] 4f 0a [2] 54 0c [2] 48 0b [2] 54 24 }

  condition:
    any of them
}