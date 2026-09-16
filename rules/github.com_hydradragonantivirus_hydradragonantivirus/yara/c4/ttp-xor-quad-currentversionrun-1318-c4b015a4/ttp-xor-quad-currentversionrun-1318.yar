rule TTP_XOR_QUAD_CurrentVersionRun_1318 {
  strings:
    $key_1318 = { 40 77 [2] 64 79 [2] 4f 55 [2] 61 77 [2] 75 6c [2] 7a 76 [2] 64 6b [2] 66 6a [2] 7d 6c [2] 61 6b [2] 7d 44 }

  condition:
    any of them
}