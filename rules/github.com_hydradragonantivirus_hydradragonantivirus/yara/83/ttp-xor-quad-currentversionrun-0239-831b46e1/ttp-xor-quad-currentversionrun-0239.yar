rule TTP_XOR_QUAD_CurrentVersionRun_0239 {
  strings:
    $key_0239 = { 51 56 [2] 75 58 [2] 5e 74 [2] 70 56 [2] 64 4d [2] 6b 57 [2] 75 4a [2] 77 4b [2] 6c 4d [2] 70 4a [2] 6c 65 }

  condition:
    any of them
}