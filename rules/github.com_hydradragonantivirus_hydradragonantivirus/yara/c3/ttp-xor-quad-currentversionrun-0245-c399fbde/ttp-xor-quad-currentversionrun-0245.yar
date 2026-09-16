rule TTP_XOR_QUAD_CurrentVersionRun_0245 {
  strings:
    $key_0245 = { 51 2a [2] 75 24 [2] 5e 08 [2] 70 2a [2] 64 31 [2] 6b 2b [2] 75 36 [2] 77 37 [2] 6c 31 [2] 70 36 [2] 6c 19 }

  condition:
    any of them
}