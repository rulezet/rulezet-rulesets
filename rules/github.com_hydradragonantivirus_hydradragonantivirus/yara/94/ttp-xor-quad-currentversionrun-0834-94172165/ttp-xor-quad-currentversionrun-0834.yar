rule TTP_XOR_QUAD_CurrentVersionRun_0834 {
  strings:
    $key_0834 = { 5b 5b [2] 7f 55 [2] 54 79 [2] 7a 5b [2] 6e 40 [2] 61 5a [2] 7f 47 [2] 7d 46 [2] 66 40 [2] 7a 47 [2] 66 68 }

  condition:
    any of them
}