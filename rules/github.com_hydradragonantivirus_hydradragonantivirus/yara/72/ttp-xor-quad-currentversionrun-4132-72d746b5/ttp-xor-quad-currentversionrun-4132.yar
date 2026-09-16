rule TTP_XOR_QUAD_CurrentVersionRun_4132 {
  strings:
    $key_4132 = { 12 5d [2] 36 53 [2] 1d 7f [2] 33 5d [2] 27 46 [2] 28 5c [2] 36 41 [2] 34 40 [2] 2f 46 [2] 33 41 [2] 2f 6e }

  condition:
    any of them
}