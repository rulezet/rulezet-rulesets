rule TTP_XOR_QUAD_CurrentVersionRun_ff7a {
  strings:
    $key_ff7a = { ac 15 [2] 88 1b [2] a3 37 [2] 8d 15 [2] 99 0e [2] 96 14 [2] 88 09 [2] 8a 08 [2] 91 0e [2] 8d 09 [2] 91 26 }

  condition:
    any of them
}