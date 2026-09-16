rule TTP_XOR_QUAD_CurrentVersionRun_412c {
  strings:
    $key_412c = { 12 43 [2] 36 4d [2] 1d 61 [2] 33 43 [2] 27 58 [2] 28 42 [2] 36 5f [2] 34 5e [2] 2f 58 [2] 33 5f [2] 2f 70 }

  condition:
    any of them
}