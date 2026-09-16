rule TTP_XOR_QUAD_CurrentVersionRun_ff4c {
  strings:
    $key_ff4c = { ac 23 [2] 88 2d [2] a3 01 [2] 8d 23 [2] 99 38 [2] 96 22 [2] 88 3f [2] 8a 3e [2] 91 38 [2] 8d 3f [2] 91 10 }

  condition:
    any of them
}