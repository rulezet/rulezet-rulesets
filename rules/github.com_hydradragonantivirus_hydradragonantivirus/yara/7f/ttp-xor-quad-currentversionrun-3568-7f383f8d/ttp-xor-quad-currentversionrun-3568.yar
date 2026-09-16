rule TTP_XOR_QUAD_CurrentVersionRun_3568 {
  strings:
    $key_3568 = { 66 07 [2] 42 09 [2] 69 25 [2] 47 07 [2] 53 1c [2] 5c 06 [2] 42 1b [2] 40 1a [2] 5b 1c [2] 47 1b [2] 5b 34 }

  condition:
    any of them
}