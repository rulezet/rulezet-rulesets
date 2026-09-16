rule TTP_XOR_QUAD_CurrentVersionRun_4133 {
  strings:
    $key_4133 = { 12 5c [2] 36 52 [2] 1d 7e [2] 33 5c [2] 27 47 [2] 28 5d [2] 36 40 [2] 34 41 [2] 2f 47 [2] 33 40 [2] 2f 6f }

  condition:
    any of them
}