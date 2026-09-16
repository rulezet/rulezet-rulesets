rule TTP_XOR_QUAD_CurrentVersionRun_3004 {
  strings:
    $key_3004 = { 63 6b [2] 47 65 [2] 6c 49 [2] 42 6b [2] 56 70 [2] 59 6a [2] 47 77 [2] 45 76 [2] 5e 70 [2] 42 77 [2] 5e 58 }

  condition:
    any of them
}