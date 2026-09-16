rule TTP_XOR_QUAD_CurrentVersionRun_4151 {
  strings:
    $key_4151 = { 12 3e [2] 36 30 [2] 1d 1c [2] 33 3e [2] 27 25 [2] 28 3f [2] 36 22 [2] 34 23 [2] 2f 25 [2] 33 22 [2] 2f 0d }

  condition:
    any of them
}