rule TTP_XOR_QUAD_CurrentVersionRun_0d48 {
  strings:
    $key_0d48 = { 5e 27 [2] 7a 29 [2] 51 05 [2] 7f 27 [2] 6b 3c [2] 64 26 [2] 7a 3b [2] 78 3a [2] 63 3c [2] 7f 3b [2] 63 14 }

  condition:
    any of them
}