rule TTP_XOR_QUAD_CurrentVersionRun_2e79 {
  strings:
    $key_2e79 = { 7d 16 [2] 59 18 [2] 72 34 [2] 5c 16 [2] 48 0d [2] 47 17 [2] 59 0a [2] 5b 0b [2] 40 0d [2] 5c 0a [2] 40 25 }

  condition:
    any of them
}