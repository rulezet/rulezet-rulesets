rule TTP_XOR_QUAD_CurrentVersionRun_ff7f {
  strings:
    $key_ff7f = { ac 10 [2] 88 1e [2] a3 32 [2] 8d 10 [2] 99 0b [2] 96 11 [2] 88 0c [2] 8a 0d [2] 91 0b [2] 8d 0c [2] 91 23 }

  condition:
    any of them
}