rule TTP_XOR_QUAD_CurrentVersionRun_f205 {
  strings:
    $key_f205 = { a1 6a [2] 85 64 [2] ae 48 [2] 80 6a [2] 94 71 [2] 9b 6b [2] 85 76 [2] 87 77 [2] 9c 71 [2] 80 76 [2] 9c 59 }

  condition:
    any of them
}