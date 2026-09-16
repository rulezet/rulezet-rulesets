rule TTP_XOR_QUAD_CurrentVersionRun_ff4a {
  strings:
    $key_ff4a = { ac 25 [2] 88 2b [2] a3 07 [2] 8d 25 [2] 99 3e [2] 96 24 [2] 88 39 [2] 8a 38 [2] 91 3e [2] 8d 39 [2] 91 16 }

  condition:
    any of them
}