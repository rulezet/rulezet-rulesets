rule TTP_XOR_QUAD_CurrentVersionRun_3839 {
  strings:
    $key_3839 = { 6b 56 [2] 4f 58 [2] 64 74 [2] 4a 56 [2] 5e 4d [2] 51 57 [2] 4f 4a [2] 4d 4b [2] 56 4d [2] 4a 4a [2] 56 65 }

  condition:
    any of them
}