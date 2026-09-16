rule TTP_XOR_QUAD_CurrentVersionRun_ff50 {
  strings:
    $key_ff50 = { ac 3f [2] 88 31 [2] a3 1d [2] 8d 3f [2] 99 24 [2] 96 3e [2] 88 23 [2] 8a 22 [2] 91 24 [2] 8d 23 [2] 91 0c }

  condition:
    any of them
}