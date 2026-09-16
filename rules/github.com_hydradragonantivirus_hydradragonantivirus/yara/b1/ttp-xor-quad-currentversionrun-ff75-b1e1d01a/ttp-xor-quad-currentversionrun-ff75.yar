rule TTP_XOR_QUAD_CurrentVersionRun_ff75 {
  strings:
    $key_ff75 = { ac 1a [2] 88 14 [2] a3 38 [2] 8d 1a [2] 99 01 [2] 96 1b [2] 88 06 [2] 8a 07 [2] 91 01 [2] 8d 06 [2] 91 29 }

  condition:
    any of them
}