rule TTP_XOR_QUAD_CurrentVersionRun_0117 {
  strings:
    $key_0117 = { 52 78 [2] 76 76 [2] 5d 5a [2] 73 78 [2] 67 63 [2] 68 79 [2] 76 64 [2] 74 65 [2] 6f 63 [2] 73 64 [2] 6f 4b }

  condition:
    any of them
}