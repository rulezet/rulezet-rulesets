rule TTP_XOR_QUAD_CurrentVersionRun_412b {
  strings:
    $key_412b = { 12 44 [2] 36 4a [2] 1d 66 [2] 33 44 [2] 27 5f [2] 28 45 [2] 36 58 [2] 34 59 [2] 2f 5f [2] 33 58 [2] 2f 77 }

  condition:
    any of them
}