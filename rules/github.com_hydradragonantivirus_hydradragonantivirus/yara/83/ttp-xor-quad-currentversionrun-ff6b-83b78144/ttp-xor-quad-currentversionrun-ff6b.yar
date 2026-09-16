rule TTP_XOR_QUAD_CurrentVersionRun_ff6b {
  strings:
    $key_ff6b = { ac 04 [2] 88 0a [2] a3 26 [2] 8d 04 [2] 99 1f [2] 96 05 [2] 88 18 [2] 8a 19 [2] 91 1f [2] 8d 18 [2] 91 37 }

  condition:
    any of them
}