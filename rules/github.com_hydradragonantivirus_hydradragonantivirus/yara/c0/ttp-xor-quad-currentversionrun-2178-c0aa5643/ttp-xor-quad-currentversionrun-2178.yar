rule TTP_XOR_QUAD_CurrentVersionRun_2178 {
  strings:
    $key_2178 = { 72 17 [2] 56 19 [2] 7d 35 [2] 53 17 [2] 47 0c [2] 48 16 [2] 56 0b [2] 54 0a [2] 4f 0c [2] 53 0b [2] 4f 24 }

  condition:
    any of them
}