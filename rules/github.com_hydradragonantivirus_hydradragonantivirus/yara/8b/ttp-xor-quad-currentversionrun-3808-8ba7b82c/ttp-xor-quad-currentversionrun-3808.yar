rule TTP_XOR_QUAD_CurrentVersionRun_3808 {
  strings:
    $key_3808 = { 6b 67 [2] 4f 69 [2] 64 45 [2] 4a 67 [2] 5e 7c [2] 51 66 [2] 4f 7b [2] 4d 7a [2] 56 7c [2] 4a 7b [2] 56 54 }

  condition:
    any of them
}