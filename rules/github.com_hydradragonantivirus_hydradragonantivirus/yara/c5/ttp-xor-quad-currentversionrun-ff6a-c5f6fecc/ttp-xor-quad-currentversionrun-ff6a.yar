rule TTP_XOR_QUAD_CurrentVersionRun_ff6a {
  strings:
    $key_ff6a = { ac 05 [2] 88 0b [2] a3 27 [2] 8d 05 [2] 99 1e [2] 96 04 [2] 88 19 [2] 8a 18 [2] 91 1e [2] 8d 19 [2] 91 36 }

  condition:
    any of them
}