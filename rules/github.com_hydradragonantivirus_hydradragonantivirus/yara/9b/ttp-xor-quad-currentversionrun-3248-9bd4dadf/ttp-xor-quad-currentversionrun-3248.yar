rule TTP_XOR_QUAD_CurrentVersionRun_3248 {
  strings:
    $key_3248 = { 61 27 [2] 45 29 [2] 6e 05 [2] 40 27 [2] 54 3c [2] 5b 26 [2] 45 3b [2] 47 3a [2] 5c 3c [2] 40 3b [2] 5c 14 }

  condition:
    any of them
}