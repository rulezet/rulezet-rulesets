rule TTP_XOR_QUAD_CurrentVersionRun_0417 {
  strings:
    $key_0417 = { 57 78 [2] 73 76 [2] 58 5a [2] 76 78 [2] 62 63 [2] 6d 79 [2] 73 64 [2] 71 65 [2] 6a 63 [2] 76 64 [2] 6a 4b }

  condition:
    any of them
}