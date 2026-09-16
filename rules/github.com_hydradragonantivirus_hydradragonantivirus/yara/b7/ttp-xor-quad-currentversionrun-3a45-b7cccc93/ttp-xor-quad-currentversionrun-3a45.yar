rule TTP_XOR_QUAD_CurrentVersionRun_3a45 {
  strings:
    $key_3a45 = { 69 2a [2] 4d 24 [2] 66 08 [2] 48 2a [2] 5c 31 [2] 53 2b [2] 4d 36 [2] 4f 37 [2] 54 31 [2] 48 36 [2] 54 19 }

  condition:
    any of them
}