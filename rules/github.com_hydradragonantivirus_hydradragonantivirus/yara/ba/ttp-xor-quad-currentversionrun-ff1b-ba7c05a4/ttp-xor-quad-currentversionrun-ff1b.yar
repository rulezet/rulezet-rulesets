rule TTP_XOR_QUAD_CurrentVersionRun_ff1b {
  strings:
    $key_ff1b = { ac 74 [2] 88 7a [2] a3 56 [2] 8d 74 [2] 99 6f [2] 96 75 [2] 88 68 [2] 8a 69 [2] 91 6f [2] 8d 68 [2] 91 47 }

  condition:
    any of them
}