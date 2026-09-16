rule TTP_XOR_QUAD_CurrentVersionRun_2119 {
  strings:
    $key_2119 = { 72 76 [2] 56 78 [2] 7d 54 [2] 53 76 [2] 47 6d [2] 48 77 [2] 56 6a [2] 54 6b [2] 4f 6d [2] 53 6a [2] 4f 45 }

  condition:
    any of them
}