rule TTP_XOR_QUAD_CurrentVersionRun_ff62 {
  strings:
    $key_ff62 = { ac 0d [2] 88 03 [2] a3 2f [2] 8d 0d [2] 99 16 [2] 96 0c [2] 88 11 [2] 8a 10 [2] 91 16 [2] 8d 11 [2] 91 3e }

  condition:
    any of them
}