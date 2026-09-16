rule TTP_XOR_QUAD_CurrentVersionRun_4102 {
  strings:
    $key_4102 = { 12 6d [2] 36 63 [2] 1d 4f [2] 33 6d [2] 27 76 [2] 28 6c [2] 36 71 [2] 34 70 [2] 2f 76 [2] 33 71 [2] 2f 5e }

  condition:
    any of them
}