rule TTP_XOR_QUAD_CurrentVersionRun_3005 {
  strings:
    $key_3005 = { 63 6a [2] 47 64 [2] 6c 48 [2] 42 6a [2] 56 71 [2] 59 6b [2] 47 76 [2] 45 77 [2] 5e 71 [2] 42 76 [2] 5e 59 }

  condition:
    any of them
}