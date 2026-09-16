rule TTP_XOR_QUAD_CurrentVersionRun_ff51 {
  strings:
    $key_ff51 = { ac 3e [2] 88 30 [2] a3 1c [2] 8d 3e [2] 99 25 [2] 96 3f [2] 88 22 [2] 8a 23 [2] 91 25 [2] 8d 22 [2] 91 0d }

  condition:
    any of them
}