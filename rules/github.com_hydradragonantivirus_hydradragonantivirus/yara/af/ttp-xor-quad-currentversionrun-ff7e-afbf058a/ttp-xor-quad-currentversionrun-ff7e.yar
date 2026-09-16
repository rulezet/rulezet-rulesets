rule TTP_XOR_QUAD_CurrentVersionRun_ff7e {
  strings:
    $key_ff7e = { ac 11 [2] 88 1f [2] a3 33 [2] 8d 11 [2] 99 0a [2] 96 10 [2] 88 0d [2] 8a 0c [2] 91 0a [2] 8d 0d [2] 91 22 }

  condition:
    any of them
}