rule TTP_XOR_QUAD_CurrentVersionRun_3a68 {
  strings:
    $key_3a68 = { 69 07 [2] 4d 09 [2] 66 25 [2] 48 07 [2] 5c 1c [2] 53 06 [2] 4d 1b [2] 4f 1a [2] 54 1c [2] 48 1b [2] 54 34 }

  condition:
    any of them
}