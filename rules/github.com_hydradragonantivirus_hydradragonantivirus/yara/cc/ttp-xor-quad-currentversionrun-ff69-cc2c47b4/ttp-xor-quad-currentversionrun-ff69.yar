rule TTP_XOR_QUAD_CurrentVersionRun_ff69 {
  strings:
    $key_ff69 = { ac 06 [2] 88 08 [2] a3 24 [2] 8d 06 [2] 99 1d [2] 96 07 [2] 88 1a [2] 8a 1b [2] 91 1d [2] 8d 1a [2] 91 35 }

  condition:
    any of them
}