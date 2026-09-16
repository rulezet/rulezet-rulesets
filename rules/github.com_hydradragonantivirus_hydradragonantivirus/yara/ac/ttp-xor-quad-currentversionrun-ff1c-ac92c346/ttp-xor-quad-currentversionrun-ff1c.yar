rule TTP_XOR_QUAD_CurrentVersionRun_ff1c {
  strings:
    $key_ff1c = { ac 73 [2] 88 7d [2] a3 51 [2] 8d 73 [2] 99 68 [2] 96 72 [2] 88 6f [2] 8a 6e [2] 91 68 [2] 8d 6f [2] 91 40 }

  condition:
    any of them
}