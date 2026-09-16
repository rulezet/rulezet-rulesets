rule TTP_XOR_QUAD_CurrentVersionRun_0d39 {
  strings:
    $key_0d39 = { 5e 56 [2] 7a 58 [2] 51 74 [2] 7f 56 [2] 6b 4d [2] 64 57 [2] 7a 4a [2] 78 4b [2] 63 4d [2] 7f 4a [2] 63 65 }

  condition:
    any of them
}