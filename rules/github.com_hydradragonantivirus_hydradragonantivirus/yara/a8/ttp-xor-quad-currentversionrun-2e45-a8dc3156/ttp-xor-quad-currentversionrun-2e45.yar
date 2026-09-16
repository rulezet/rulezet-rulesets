rule TTP_XOR_QUAD_CurrentVersionRun_2e45 {
  strings:
    $key_2e45 = { 7d 2a [2] 59 24 [2] 72 08 [2] 5c 2a [2] 48 31 [2] 47 2b [2] 59 36 [2] 5b 37 [2] 40 31 [2] 5c 36 [2] 40 19 }

  condition:
    any of them
}