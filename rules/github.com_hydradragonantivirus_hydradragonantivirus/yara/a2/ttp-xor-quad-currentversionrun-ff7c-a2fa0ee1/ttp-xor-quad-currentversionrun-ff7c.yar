rule TTP_XOR_QUAD_CurrentVersionRun_ff7c {
  strings:
    $key_ff7c = { ac 13 [2] 88 1d [2] a3 31 [2] 8d 13 [2] 99 08 [2] 96 12 [2] 88 0f [2] 8a 0e [2] 91 08 [2] 8d 0f [2] 91 20 }

  condition:
    any of them
}