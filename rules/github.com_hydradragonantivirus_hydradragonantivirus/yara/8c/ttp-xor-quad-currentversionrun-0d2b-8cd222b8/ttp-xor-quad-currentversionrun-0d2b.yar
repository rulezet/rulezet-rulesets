rule TTP_XOR_QUAD_CurrentVersionRun_0d2b {
  strings:
    $key_0d2b = { 5e 44 [2] 7a 4a [2] 51 66 [2] 7f 44 [2] 6b 5f [2] 64 45 [2] 7a 58 [2] 78 59 [2] 63 5f [2] 7f 58 [2] 63 77 }

  condition:
    any of them
}