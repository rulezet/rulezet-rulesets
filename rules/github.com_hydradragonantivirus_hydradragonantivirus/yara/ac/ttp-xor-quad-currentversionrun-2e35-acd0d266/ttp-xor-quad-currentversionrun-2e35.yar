rule TTP_XOR_QUAD_CurrentVersionRun_2e35 {
  strings:
    $key_2e35 = { 7d 5a [2] 59 54 [2] 72 78 [2] 5c 5a [2] 48 41 [2] 47 5b [2] 59 46 [2] 5b 47 [2] 40 41 [2] 5c 46 [2] 40 69 }

  condition:
    any of them
}