rule TTP_XOR_QUAD_CurrentVersionRun_ff10 {
  strings:
    $key_ff10 = { ac 7f [2] 88 71 [2] a3 5d [2] 8d 7f [2] 99 64 [2] 96 7e [2] 88 63 [2] 8a 62 [2] 91 64 [2] 8d 63 [2] 91 4c }

  condition:
    any of them
}