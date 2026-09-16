rule TTP_XOR_QUAD_CurrentVersionRun_ff07 {
  strings:
    $key_ff07 = { ac 68 [2] 88 66 [2] a3 4a [2] 8d 68 [2] 99 73 [2] 96 69 [2] 88 74 [2] 8a 75 [2] 91 73 [2] 8d 74 [2] 91 5b }

  condition:
    any of them
}