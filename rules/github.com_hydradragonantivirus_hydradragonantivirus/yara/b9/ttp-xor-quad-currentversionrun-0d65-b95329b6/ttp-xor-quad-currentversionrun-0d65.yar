rule TTP_XOR_QUAD_CurrentVersionRun_0d65 {
  strings:
    $key_0d65 = { 5e 0a [2] 7a 04 [2] 51 28 [2] 7f 0a [2] 6b 11 [2] 64 0b [2] 7a 16 [2] 78 17 [2] 63 11 [2] 7f 16 [2] 63 39 }

  condition:
    any of them
}