rule TTP_XOR_QUAD_CurrentVersionRun_ff2e {
  strings:
    $key_ff2e = { ac 41 [2] 88 4f [2] a3 63 [2] 8d 41 [2] 99 5a [2] 96 40 [2] 88 5d [2] 8a 5c [2] 91 5a [2] 8d 5d [2] 91 72 }

  condition:
    any of them
}