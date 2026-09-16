rule TTP_XOR_QUAD_CurrentVersionRun_0d05 {
  strings:
    $key_0d05 = { 5e 6a [2] 7a 64 [2] 51 48 [2] 7f 6a [2] 6b 71 [2] 64 6b [2] 7a 76 [2] 78 77 [2] 63 71 [2] 7f 76 [2] 63 59 }

  condition:
    any of them
}