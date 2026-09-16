rule TTP_XOR_QUAD_CurrentVersionRun_ff2c {
  strings:
    $key_ff2c = { ac 43 [2] 88 4d [2] a3 61 [2] 8d 43 [2] 99 58 [2] 96 42 [2] 88 5f [2] 8a 5e [2] 91 58 [2] 8d 5f [2] 91 70 }

  condition:
    any of them
}