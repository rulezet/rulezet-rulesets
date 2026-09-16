rule TTP_XOR_QUAD_CurrentVersionRun_f433 {
  strings:
    $key_f433 = { a7 5c [2] 83 52 [2] a8 7e [2] 86 5c [2] 92 47 [2] 9d 5d [2] 83 40 [2] 81 41 [2] 9a 47 [2] 86 40 [2] 9a 6f }

  condition:
    any of them
}