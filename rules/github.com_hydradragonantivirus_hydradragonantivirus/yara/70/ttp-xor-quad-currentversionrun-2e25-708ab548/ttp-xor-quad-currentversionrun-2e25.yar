rule TTP_XOR_QUAD_CurrentVersionRun_2e25 {
  strings:
    $key_2e25 = { 7d 4a [2] 59 44 [2] 72 68 [2] 5c 4a [2] 48 51 [2] 47 4b [2] 59 56 [2] 5b 57 [2] 40 51 [2] 5c 56 [2] 40 79 }

  condition:
    any of them
}