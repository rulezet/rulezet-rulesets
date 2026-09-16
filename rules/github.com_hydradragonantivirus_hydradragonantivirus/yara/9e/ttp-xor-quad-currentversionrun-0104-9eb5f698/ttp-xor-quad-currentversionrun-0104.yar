rule TTP_XOR_QUAD_CurrentVersionRun_0104 {
  strings:
    $key_0104 = { 52 6b [2] 76 65 [2] 5d 49 [2] 73 6b [2] 67 70 [2] 68 6a [2] 76 77 [2] 74 76 [2] 6f 70 [2] 73 77 [2] 6f 58 }

  condition:
    any of them
}