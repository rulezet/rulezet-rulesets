rule TTP_XOR_QUAD_CurrentVersionRun_0255 {
  strings:
    $key_0255 = { 51 3a [2] 75 34 [2] 5e 18 [2] 70 3a [2] 64 21 [2] 6b 3b [2] 75 26 [2] 77 27 [2] 6c 21 [2] 70 26 [2] 6c 09 }

  condition:
    any of them
}