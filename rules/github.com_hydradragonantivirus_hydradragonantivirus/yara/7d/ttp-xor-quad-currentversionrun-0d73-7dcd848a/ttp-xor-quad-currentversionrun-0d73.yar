rule TTP_XOR_QUAD_CurrentVersionRun_0d73 {
  strings:
    $key_0d73 = { 5e 1c [2] 7a 12 [2] 51 3e [2] 7f 1c [2] 6b 07 [2] 64 1d [2] 7a 00 [2] 78 01 [2] 63 07 [2] 7f 00 [2] 63 2f }

  condition:
    any of them
}