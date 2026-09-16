rule TTP_XOR_QUAD_CurrentVersionRun_0d66 {
  strings:
    $key_0d66 = { 5e 09 [2] 7a 07 [2] 51 2b [2] 7f 09 [2] 6b 12 [2] 64 08 [2] 7a 15 [2] 78 14 [2] 63 12 [2] 7f 15 [2] 63 3a }

  condition:
    any of them
}