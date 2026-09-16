rule TTP_XOR_QUAD_CurrentVersionRun_0868 {
  strings:
    $key_0868 = { 5b 07 [2] 7f 09 [2] 54 25 [2] 7a 07 [2] 6e 1c [2] 61 06 [2] 7f 1b [2] 7d 1a [2] 66 1c [2] 7a 1b [2] 66 34 }

  condition:
    any of them
}