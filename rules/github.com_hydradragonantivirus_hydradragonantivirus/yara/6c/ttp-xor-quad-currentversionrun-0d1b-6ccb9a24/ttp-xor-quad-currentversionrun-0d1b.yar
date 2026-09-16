rule TTP_XOR_QUAD_CurrentVersionRun_0d1b {
  strings:
    $key_0d1b = { 5e 74 [2] 7a 7a [2] 51 56 [2] 7f 74 [2] 6b 6f [2] 64 75 [2] 7a 68 [2] 78 69 [2] 63 6f [2] 7f 68 [2] 63 47 }

  condition:
    any of them
}