rule TTP_XOR_QUAD_CurrentVersionRun_382b {
  strings:
    $key_382b = { 6b 44 [2] 4f 4a [2] 64 66 [2] 4a 44 [2] 5e 5f [2] 51 45 [2] 4f 58 [2] 4d 59 [2] 56 5f [2] 4a 58 [2] 56 77 }

  condition:
    any of them
}