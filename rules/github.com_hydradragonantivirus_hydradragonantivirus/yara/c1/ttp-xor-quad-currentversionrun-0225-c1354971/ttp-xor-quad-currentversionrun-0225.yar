rule TTP_XOR_QUAD_CurrentVersionRun_0225 {
  strings:
    $key_0225 = { 51 4a [2] 75 44 [2] 5e 68 [2] 70 4a [2] 64 51 [2] 6b 4b [2] 75 56 [2] 77 57 [2] 6c 51 [2] 70 56 [2] 6c 79 }

  condition:
    any of them
}