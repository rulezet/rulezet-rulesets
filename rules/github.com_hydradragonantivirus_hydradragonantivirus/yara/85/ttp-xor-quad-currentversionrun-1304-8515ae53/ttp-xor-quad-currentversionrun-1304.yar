rule TTP_XOR_QUAD_CurrentVersionRun_1304 {
  strings:
    $key_1304 = { 40 6b [2] 64 65 [2] 4f 49 [2] 61 6b [2] 75 70 [2] 7a 6a [2] 64 77 [2] 66 76 [2] 7d 70 [2] 61 77 [2] 7d 58 }

  condition:
    any of them
}