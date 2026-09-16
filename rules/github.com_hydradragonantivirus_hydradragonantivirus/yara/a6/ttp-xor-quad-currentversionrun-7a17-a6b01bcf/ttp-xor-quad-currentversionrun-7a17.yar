rule TTP_XOR_QUAD_CurrentVersionRun_7a17 {
  strings:
    $key_7a17 = { 29 78 [2] 0d 76 [2] 26 5a [2] 08 78 [2] 1c 63 [2] 13 79 [2] 0d 64 [2] 0f 65 [2] 14 63 [2] 08 64 [2] 14 4b }

  condition:
    any of them
}