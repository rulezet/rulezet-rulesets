rule TTP_XOR_QUAD_CurrentVersionRun_3744 {
  strings:
    $key_3744 = { 64 2b [2] 40 25 [2] 6b 09 [2] 45 2b [2] 51 30 [2] 5e 2a [2] 40 37 [2] 42 36 [2] 59 30 [2] 45 37 [2] 59 18 }

  condition:
    any of them
}