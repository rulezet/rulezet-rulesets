rule TTP_XOR_QUAD_CurrentVersionRun_1817 {
  strings:
    $key_1817 = { 4b 78 [2] 6f 76 [2] 44 5a [2] 6a 78 [2] 7e 63 [2] 71 79 [2] 6f 64 [2] 6d 65 [2] 76 63 [2] 6a 64 [2] 76 4b }

  condition:
    any of them
}