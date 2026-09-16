rule TTP_XOR_QUAD_CurrentVersionRun_ff5e {
  strings:
    $key_ff5e = { ac 31 [2] 88 3f [2] a3 13 [2] 8d 31 [2] 99 2a [2] 96 30 [2] 88 2d [2] 8a 2c [2] 91 2a [2] 8d 2d [2] 91 02 }

  condition:
    any of them
}