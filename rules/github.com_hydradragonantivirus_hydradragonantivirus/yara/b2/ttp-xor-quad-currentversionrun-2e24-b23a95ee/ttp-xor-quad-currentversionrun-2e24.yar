rule TTP_XOR_QUAD_CurrentVersionRun_2e24 {
  strings:
    $key_2e24 = { 7d 4b [2] 59 45 [2] 72 69 [2] 5c 4b [2] 48 50 [2] 47 4a [2] 59 57 [2] 5b 56 [2] 40 50 [2] 5c 57 [2] 40 78 }

  condition:
    any of them
}