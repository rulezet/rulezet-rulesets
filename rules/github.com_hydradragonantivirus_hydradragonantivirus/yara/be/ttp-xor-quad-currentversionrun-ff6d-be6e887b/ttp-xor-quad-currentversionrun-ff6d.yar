rule TTP_XOR_QUAD_CurrentVersionRun_ff6d {
  strings:
    $key_ff6d = { ac 02 [2] 88 0c [2] a3 20 [2] 8d 02 [2] 99 19 [2] 96 03 [2] 88 1e [2] 8a 1f [2] 91 19 [2] 8d 1e [2] 91 31 }

  condition:
    any of them
}