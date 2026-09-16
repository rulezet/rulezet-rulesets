rule TTP_XOR_QUAD_CurrentVersionRun_f411 {
  strings:
    $key_f411 = { a7 7e [2] 83 70 [2] a8 5c [2] 86 7e [2] 92 65 [2] 9d 7f [2] 83 62 [2] 81 63 [2] 9a 65 [2] 86 62 [2] 9a 4d }

  condition:
    any of them
}