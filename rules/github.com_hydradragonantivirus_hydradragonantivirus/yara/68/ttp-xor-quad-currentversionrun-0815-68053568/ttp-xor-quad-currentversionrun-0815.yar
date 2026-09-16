rule TTP_XOR_QUAD_CurrentVersionRun_0815 {
  strings:
    $key_0815 = { 5b 7a [2] 7f 74 [2] 54 58 [2] 7a 7a [2] 6e 61 [2] 61 7b [2] 7f 66 [2] 7d 67 [2] 66 61 [2] 7a 66 [2] 66 49 }

  condition:
    any of them
}