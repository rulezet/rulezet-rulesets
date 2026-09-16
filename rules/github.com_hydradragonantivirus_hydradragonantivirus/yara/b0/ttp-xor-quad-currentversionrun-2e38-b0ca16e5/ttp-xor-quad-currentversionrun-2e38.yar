rule TTP_XOR_QUAD_CurrentVersionRun_2e38 {
  strings:
    $key_2e38 = { 7d 57 [2] 59 59 [2] 72 75 [2] 5c 57 [2] 48 4c [2] 47 56 [2] 59 4b [2] 5b 4a [2] 40 4c [2] 5c 4b [2] 40 64 }

  condition:
    any of them
}