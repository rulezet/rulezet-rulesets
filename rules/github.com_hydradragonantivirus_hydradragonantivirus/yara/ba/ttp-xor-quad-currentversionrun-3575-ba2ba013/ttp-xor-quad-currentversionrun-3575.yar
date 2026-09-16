rule TTP_XOR_QUAD_CurrentVersionRun_3575 {
  strings:
    $key_3575 = { 66 1a [2] 42 14 [2] 69 38 [2] 47 1a [2] 53 01 [2] 5c 1b [2] 42 06 [2] 40 07 [2] 5b 01 [2] 47 06 [2] 5b 29 }

  condition:
    any of them
}