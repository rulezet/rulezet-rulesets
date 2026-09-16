rule TTP_XOR_QUAD_CurrentVersionRun_0a5b {
  strings:
    $key_0a5b = { 59 34 [2] 7d 3a [2] 56 16 [2] 78 34 [2] 6c 2f [2] 63 35 [2] 7d 28 [2] 7f 29 [2] 64 2f [2] 78 28 [2] 64 07 }

  condition:
    any of them
}