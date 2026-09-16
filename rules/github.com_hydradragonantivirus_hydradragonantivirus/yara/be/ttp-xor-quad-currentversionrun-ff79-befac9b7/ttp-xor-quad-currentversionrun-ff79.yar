rule TTP_XOR_QUAD_CurrentVersionRun_ff79 {
  strings:
    $key_ff79 = { ac 16 [2] 88 18 [2] a3 34 [2] 8d 16 [2] 99 0d [2] 96 17 [2] 88 0a [2] 8a 0b [2] 91 0d [2] 8d 0a [2] 91 25 }

  condition:
    any of them
}