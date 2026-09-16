rule TTP_XOR_QUAD_CurrentVersionRun_0839 {
  strings:
    $key_0839 = { 5b 56 [2] 7f 58 [2] 54 74 [2] 7a 56 [2] 6e 4d [2] 61 57 [2] 7f 4a [2] 7d 4b [2] 66 4d [2] 7a 4a [2] 66 65 }

  condition:
    any of them
}