rule TTP_XOR_QUAD_CurrentVersionRun_165b {
  strings:
    $key_165b = { 45 34 [2] 61 3a [2] 4a 16 [2] 64 34 [2] 70 2f [2] 7f 35 [2] 61 28 [2] 63 29 [2] 78 2f [2] 64 28 [2] 78 07 }

  condition:
    any of them
}