rule TTP_XOR_QUAD_CurrentVersionRun_3754 {
  strings:
    $key_3754 = { 64 3b [2] 40 35 [2] 6b 19 [2] 45 3b [2] 51 20 [2] 5e 3a [2] 40 27 [2] 42 26 [2] 59 20 [2] 45 27 [2] 59 08 }

  condition:
    any of them
}