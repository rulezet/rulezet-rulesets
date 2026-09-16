rule TTP_XOR_QUAD_CurrentVersionRun_ff67 {
  strings:
    $key_ff67 = { ac 08 [2] 88 06 [2] a3 2a [2] 8d 08 [2] 99 13 [2] 96 09 [2] 88 14 [2] 8a 15 [2] 91 13 [2] 8d 14 [2] 91 3b }

  condition:
    any of them
}