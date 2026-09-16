rule TTP_XOR_QUAD_CurrentVersionRun_010b {
  strings:
    $key_010b = { 52 64 [2] 76 6a [2] 5d 46 [2] 73 64 [2] 67 7f [2] 68 65 [2] 76 78 [2] 74 79 [2] 6f 7f [2] 73 78 [2] 6f 57 }

  condition:
    any of them
}