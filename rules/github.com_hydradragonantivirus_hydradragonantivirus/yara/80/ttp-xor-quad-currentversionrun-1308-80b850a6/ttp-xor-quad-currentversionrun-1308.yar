rule TTP_XOR_QUAD_CurrentVersionRun_1308 {
  strings:
    $key_1308 = { 40 67 [2] 64 69 [2] 4f 45 [2] 61 67 [2] 75 7c [2] 7a 66 [2] 64 7b [2] 66 7a [2] 7d 7c [2] 61 7b [2] 7d 54 }

  condition:
    any of them
}