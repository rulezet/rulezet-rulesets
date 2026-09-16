rule TTP_XOR_QUAD_CurrentVersionRun_7878 {
  strings:
    $key_7878 = { 2b 17 [2] 0f 19 [2] 24 35 [2] 0a 17 [2] 1e 0c [2] 11 16 [2] 0f 0b [2] 0d 0a [2] 16 0c [2] 0a 0b [2] 16 24 }

  condition:
    any of them
}