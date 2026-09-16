rule TTP_XOR_QUAD_CurrentVersionRun_ff23 {
  strings:
    $key_ff23 = { ac 4c [2] 88 42 [2] a3 6e [2] 8d 4c [2] 99 57 [2] 96 4d [2] 88 50 [2] 8a 51 [2] 91 57 [2] 8d 50 [2] 91 7f }

  condition:
    any of them
}