rule TTP_XOR_QUAD_CurrentVersionRun_3704 {
  strings:
    $key_3704 = { 64 6b [2] 40 65 [2] 6b 49 [2] 45 6b [2] 51 70 [2] 5e 6a [2] 40 77 [2] 42 76 [2] 59 70 [2] 45 77 [2] 59 58 }

  condition:
    any of them
}