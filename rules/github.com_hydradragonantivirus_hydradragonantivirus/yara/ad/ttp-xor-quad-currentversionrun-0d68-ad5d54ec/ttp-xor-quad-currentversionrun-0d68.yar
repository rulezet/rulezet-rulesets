rule TTP_XOR_QUAD_CurrentVersionRun_0d68 {
  strings:
    $key_0d68 = { 5e 07 [2] 7a 09 [2] 51 25 [2] 7f 07 [2] 6b 1c [2] 64 06 [2] 7a 1b [2] 78 1a [2] 63 1c [2] 7f 1b [2] 63 34 }

  condition:
    any of them
}