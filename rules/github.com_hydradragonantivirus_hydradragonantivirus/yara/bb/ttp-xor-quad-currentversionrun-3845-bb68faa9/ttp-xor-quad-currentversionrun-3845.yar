rule TTP_XOR_QUAD_CurrentVersionRun_3845 {
  strings:
    $key_3845 = { 6b 2a [2] 4f 24 [2] 64 08 [2] 4a 2a [2] 5e 31 [2] 51 2b [2] 4f 36 [2] 4d 37 [2] 56 31 [2] 4a 36 [2] 56 19 }

  condition:
    any of them
}