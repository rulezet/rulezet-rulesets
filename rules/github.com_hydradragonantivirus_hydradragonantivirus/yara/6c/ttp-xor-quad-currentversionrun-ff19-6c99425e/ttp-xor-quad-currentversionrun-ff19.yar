rule TTP_XOR_QUAD_CurrentVersionRun_ff19 {
  strings:
    $key_ff19 = { ac 76 [2] 88 78 [2] a3 54 [2] 8d 76 [2] 99 6d [2] 96 77 [2] 88 6a [2] 8a 6b [2] 91 6d [2] 8d 6a [2] 91 45 }

  condition:
    any of them
}