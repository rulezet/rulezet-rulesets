rule TTP_XOR_QUAD_CurrentVersionRun_0d45 {
  strings:
    $key_0d45 = { 5e 2a [2] 7a 24 [2] 51 08 [2] 7f 2a [2] 6b 31 [2] 64 2b [2] 7a 36 [2] 78 37 [2] 63 31 [2] 7f 36 [2] 63 19 }

  condition:
    any of them
}