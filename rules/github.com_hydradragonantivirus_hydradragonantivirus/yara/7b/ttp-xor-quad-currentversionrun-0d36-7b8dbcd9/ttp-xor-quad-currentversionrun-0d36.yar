rule TTP_XOR_QUAD_CurrentVersionRun_0d36 {
  strings:
    $key_0d36 = { 5e 59 [2] 7a 57 [2] 51 7b [2] 7f 59 [2] 6b 42 [2] 64 58 [2] 7a 45 [2] 78 44 [2] 63 42 [2] 7f 45 [2] 63 6a }

  condition:
    any of them
}