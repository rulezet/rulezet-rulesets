rule TTP_XOR_QUAD_CurrentVersionRun_0244 {
  strings:
    $key_0244 = { 51 2b [2] 75 25 [2] 5e 09 [2] 70 2b [2] 64 30 [2] 6b 2a [2] 75 37 [2] 77 36 [2] 6c 30 [2] 70 37 [2] 6c 18 }

  condition:
    any of them
}