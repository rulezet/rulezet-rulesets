rule TTP_XOR_QUAD_CurrentVersionRun_1605 {
  strings:
    $key_1605 = { 45 6a [2] 61 64 [2] 4a 48 [2] 64 6a [2] 70 71 [2] 7f 6b [2] 61 76 [2] 63 77 [2] 78 71 [2] 64 76 [2] 78 59 }

  condition:
    any of them
}