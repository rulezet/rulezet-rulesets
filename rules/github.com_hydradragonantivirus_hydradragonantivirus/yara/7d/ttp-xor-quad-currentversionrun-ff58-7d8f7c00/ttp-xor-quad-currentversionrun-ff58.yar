rule TTP_XOR_QUAD_CurrentVersionRun_ff58 {
  strings:
    $key_ff58 = { ac 37 [2] 88 39 [2] a3 15 [2] 8d 37 [2] 99 2c [2] 96 36 [2] 88 2b [2] 8a 2a [2] 91 2c [2] 8d 2b [2] 91 04 }

  condition:
    any of them
}