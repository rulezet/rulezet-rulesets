rule TTP_XOR_QUAD_CurrentVersionRun_0a17 {
  strings:
    $key_0a17 = { 59 78 [2] 7d 76 [2] 56 5a [2] 78 78 [2] 6c 63 [2] 63 79 [2] 7d 64 [2] 7f 65 [2] 64 63 [2] 78 64 [2] 64 4b }

  condition:
    any of them
}