rule TTP_XOR_QUAD_CurrentVersionRun_ff74 {
  strings:
    $key_ff74 = { ac 1b [2] 88 15 [2] a3 39 [2] 8d 1b [2] 99 00 [2] 96 1a [2] 88 07 [2] 8a 06 [2] 91 00 [2] 8d 07 [2] 91 28 }

  condition:
    any of them
}