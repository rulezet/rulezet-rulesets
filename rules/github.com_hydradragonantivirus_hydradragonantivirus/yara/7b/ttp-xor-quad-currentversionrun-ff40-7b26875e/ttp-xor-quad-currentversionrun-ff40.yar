rule TTP_XOR_QUAD_CurrentVersionRun_ff40 {
  strings:
    $key_ff40 = { ac 2f [2] 88 21 [2] a3 0d [2] 8d 2f [2] 99 34 [2] 96 2e [2] 88 33 [2] 8a 32 [2] 91 34 [2] 8d 33 [2] 91 1c }

  condition:
    any of them
}