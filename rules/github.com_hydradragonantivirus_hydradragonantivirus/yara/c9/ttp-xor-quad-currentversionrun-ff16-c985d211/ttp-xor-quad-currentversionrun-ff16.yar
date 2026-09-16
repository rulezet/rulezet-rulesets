rule TTP_XOR_QUAD_CurrentVersionRun_ff16 {
  strings:
    $key_ff16 = { ac 79 [2] 88 77 [2] a3 5b [2] 8d 79 [2] 99 62 [2] 96 78 [2] 88 65 [2] 8a 64 [2] 91 62 [2] 8d 65 [2] 91 4a }

  condition:
    any of them
}