rule TTP_XOR_QUAD_CurrentVersionRun_0279 {
  strings:
    $key_0279 = { 51 16 [2] 75 18 [2] 5e 34 [2] 70 16 [2] 64 0d [2] 6b 17 [2] 75 0a [2] 77 0b [2] 6c 0d [2] 70 0a [2] 6c 25 }

  condition:
    any of them
}