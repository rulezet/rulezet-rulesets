rule TTP_XOR_QUAD_CurrentVersionRun_ff61 {
  strings:
    $key_ff61 = { ac 0e [2] 88 00 [2] a3 2c [2] 8d 0e [2] 99 15 [2] 96 0f [2] 88 12 [2] 8a 13 [2] 91 15 [2] 8d 12 [2] 91 3d }

  condition:
    any of them
}