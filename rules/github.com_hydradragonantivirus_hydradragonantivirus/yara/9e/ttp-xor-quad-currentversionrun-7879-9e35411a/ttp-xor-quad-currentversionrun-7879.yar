rule TTP_XOR_QUAD_CurrentVersionRun_7879 {
  strings:
    $key_7879 = { 2b 16 [2] 0f 18 [2] 24 34 [2] 0a 16 [2] 1e 0d [2] 11 17 [2] 0f 0a [2] 0d 0b [2] 16 0d [2] 0a 0a [2] 16 25 }

  condition:
    any of them
}