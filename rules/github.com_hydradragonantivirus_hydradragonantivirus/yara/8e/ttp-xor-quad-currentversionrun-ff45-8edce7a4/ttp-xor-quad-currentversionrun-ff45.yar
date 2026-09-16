rule TTP_XOR_QUAD_CurrentVersionRun_ff45 {
  strings:
    $key_ff45 = { ac 2a [2] 88 24 [2] a3 08 [2] 8d 2a [2] 99 31 [2] 96 2b [2] 88 36 [2] 8a 37 [2] 91 31 [2] 8d 36 [2] 91 19 }

  condition:
    any of them
}