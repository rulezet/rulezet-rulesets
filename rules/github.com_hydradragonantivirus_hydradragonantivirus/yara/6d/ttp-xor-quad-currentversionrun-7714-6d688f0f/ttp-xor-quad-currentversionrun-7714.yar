rule TTP_XOR_QUAD_CurrentVersionRun_7714 {
  strings:
    $key_7714 = { 24 7b [2] 00 75 [2] 2b 59 [2] 05 7b [2] 11 60 [2] 1e 7a [2] 00 67 [2] 02 66 [2] 19 60 [2] 05 67 [2] 19 48 }

  condition:
    any of them
}