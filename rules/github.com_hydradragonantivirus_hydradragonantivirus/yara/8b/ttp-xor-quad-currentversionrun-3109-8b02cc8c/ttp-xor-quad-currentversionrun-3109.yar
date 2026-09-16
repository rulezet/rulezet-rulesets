rule TTP_XOR_QUAD_CurrentVersionRun_3109 {
  strings:
    $key_3109 = { 62 66 [2] 46 68 [2] 6d 44 [2] 43 66 [2] 57 7d [2] 58 67 [2] 46 7a [2] 44 7b [2] 5f 7d [2] 43 7a [2] 5f 55 }

  condition:
    any of them
}