rule TTP_XOR_QUAD_CurrentVersionRun_0d13 {
  strings:
    $key_0d13 = { 5e 7c [2] 7a 72 [2] 51 5e [2] 7f 7c [2] 6b 67 [2] 64 7d [2] 7a 60 [2] 78 61 [2] 63 67 [2] 7f 60 [2] 63 4f }

  condition:
    any of them
}