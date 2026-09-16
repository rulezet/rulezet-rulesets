rule TTP_XOR_QUAD_CurrentVersionRun_3864 {
  strings:
    $key_3864 = { 6b 0b [2] 4f 05 [2] 64 29 [2] 4a 0b [2] 5e 10 [2] 51 0a [2] 4f 17 [2] 4d 16 [2] 56 10 [2] 4a 17 [2] 56 38 }

  condition:
    any of them
}