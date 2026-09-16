rule TTP_XOR_QUAD_CurrentVersionRun_0224 {
  strings:
    $key_0224 = { 51 4b [2] 75 45 [2] 5e 69 [2] 70 4b [2] 64 50 [2] 6b 4a [2] 75 57 [2] 77 56 [2] 6c 50 [2] 70 57 [2] 6c 78 }

  condition:
    any of them
}