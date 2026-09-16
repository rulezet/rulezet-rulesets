rule TTP_XOR_QUAD_CurrentVersionRun_ff1d {
  strings:
    $key_ff1d = { ac 72 [2] 88 7c [2] a3 50 [2] 8d 72 [2] 99 69 [2] 96 73 [2] 88 6e [2] 8a 6f [2] 91 69 [2] 8d 6e [2] 91 41 }

  condition:
    any of them
}