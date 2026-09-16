rule TTP_XOR_QUAD_CurrentVersionRun_0d19 {
  strings:
    $key_0d19 = { 5e 76 [2] 7a 78 [2] 51 54 [2] 7f 76 [2] 6b 6d [2] 64 77 [2] 7a 6a [2] 78 6b [2] 63 6d [2] 7f 6a [2] 63 45 }

  condition:
    any of them
}