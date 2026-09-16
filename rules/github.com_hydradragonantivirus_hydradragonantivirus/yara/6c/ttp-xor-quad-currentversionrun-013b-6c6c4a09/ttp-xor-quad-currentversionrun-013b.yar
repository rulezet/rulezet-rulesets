rule TTP_XOR_QUAD_CurrentVersionRun_013b {
  strings:
    $key_013b = { 52 54 [2] 76 5a [2] 5d 76 [2] 73 54 [2] 67 4f [2] 68 55 [2] 76 48 [2] 74 49 [2] 6f 4f [2] 73 48 [2] 6f 67 }

  condition:
    any of them
}