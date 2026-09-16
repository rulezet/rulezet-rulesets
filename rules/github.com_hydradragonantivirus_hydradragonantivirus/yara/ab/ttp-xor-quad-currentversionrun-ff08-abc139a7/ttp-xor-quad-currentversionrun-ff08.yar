rule TTP_XOR_QUAD_CurrentVersionRun_ff08 {
  strings:
    $key_ff08 = { ac 67 [2] 88 69 [2] a3 45 [2] 8d 67 [2] 99 7c [2] 96 66 [2] 88 7b [2] 8a 7a [2] 91 7c [2] 8d 7b [2] 91 54 }

  condition:
    any of them
}