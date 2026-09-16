rule TTP_XOR_QUAD_CurrentVersionRun_040b {
  strings:
    $key_040b = { 57 64 [2] 73 6a [2] 58 46 [2] 76 64 [2] 62 7f [2] 6d 65 [2] 73 78 [2] 71 79 [2] 6a 7f [2] 76 78 [2] 6a 57 }

  condition:
    any of them
}