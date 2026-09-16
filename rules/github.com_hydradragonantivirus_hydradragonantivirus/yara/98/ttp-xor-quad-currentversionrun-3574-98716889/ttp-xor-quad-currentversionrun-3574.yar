rule TTP_XOR_QUAD_CurrentVersionRun_3574 {
  strings:
    $key_3574 = { 66 1b [2] 42 15 [2] 69 39 [2] 47 1b [2] 53 00 [2] 5c 1a [2] 42 07 [2] 40 06 [2] 5b 00 [2] 47 07 [2] 5b 28 }

  condition:
    any of them
}