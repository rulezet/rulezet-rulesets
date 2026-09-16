rule TTP_XOR_QUAD_CurrentVersionRun_ff6c {
  strings:
    $key_ff6c = { ac 03 [2] 88 0d [2] a3 21 [2] 8d 03 [2] 99 18 [2] 96 02 [2] 88 1f [2] 8a 1e [2] 91 18 [2] 8d 1f [2] 91 30 }

  condition:
    any of them
}