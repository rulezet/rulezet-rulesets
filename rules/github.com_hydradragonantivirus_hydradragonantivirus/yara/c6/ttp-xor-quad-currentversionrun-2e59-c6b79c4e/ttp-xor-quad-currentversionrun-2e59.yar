rule TTP_XOR_QUAD_CurrentVersionRun_2e59 {
  strings:
    $key_2e59 = { 7d 36 [2] 59 38 [2] 72 14 [2] 5c 36 [2] 48 2d [2] 47 37 [2] 59 2a [2] 5b 2b [2] 40 2d [2] 5c 2a [2] 40 05 }

  condition:
    any of them
}