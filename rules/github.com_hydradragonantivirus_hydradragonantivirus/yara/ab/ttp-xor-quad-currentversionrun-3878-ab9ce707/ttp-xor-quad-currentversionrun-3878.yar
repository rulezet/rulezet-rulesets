rule TTP_XOR_QUAD_CurrentVersionRun_3878 {
  strings:
    $key_3878 = { 6b 17 [2] 4f 19 [2] 64 35 [2] 4a 17 [2] 5e 0c [2] 51 16 [2] 4f 0b [2] 4d 0a [2] 56 0c [2] 4a 0b [2] 56 24 }

  condition:
    any of them
}