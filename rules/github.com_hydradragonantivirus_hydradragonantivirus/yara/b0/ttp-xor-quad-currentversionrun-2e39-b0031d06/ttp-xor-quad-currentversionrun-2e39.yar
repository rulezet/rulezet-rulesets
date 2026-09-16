rule TTP_XOR_QUAD_CurrentVersionRun_2e39 {
  strings:
    $key_2e39 = { 7d 56 [2] 59 58 [2] 72 74 [2] 5c 56 [2] 48 4d [2] 47 57 [2] 59 4a [2] 5b 4b [2] 40 4d [2] 5c 4a [2] 40 65 }

  condition:
    any of them
}