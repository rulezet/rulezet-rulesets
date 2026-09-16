rule TTP_XOR_QUAD_CurrentVersionRun_3815 {
  strings:
    $key_3815 = { 6b 7a [2] 4f 74 [2] 64 58 [2] 4a 7a [2] 5e 61 [2] 51 7b [2] 4f 66 [2] 4d 67 [2] 56 61 [2] 4a 66 [2] 56 49 }

  condition:
    any of them
}