rule TTP_XOR_QUAD_CurrentVersionRun_ff00 {
  strings:
    $key_ff00 = { ac 6f [2] 88 61 [2] a3 4d [2] 8d 6f [2] 99 74 [2] 96 6e [2] 88 73 [2] 8a 72 [2] 91 74 [2] 8d 73 [2] 91 5c }

  condition:
    any of them
}