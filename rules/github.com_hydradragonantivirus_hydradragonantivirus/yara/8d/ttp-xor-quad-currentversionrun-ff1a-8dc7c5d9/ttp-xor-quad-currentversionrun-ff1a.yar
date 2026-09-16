rule TTP_XOR_QUAD_CurrentVersionRun_ff1a {
  strings:
    $key_ff1a = { ac 75 [2] 88 7b [2] a3 57 [2] 8d 75 [2] 99 6e [2] 96 74 [2] 88 69 [2] 8a 68 [2] 91 6e [2] 8d 69 [2] 91 46 }

  condition:
    any of them
}