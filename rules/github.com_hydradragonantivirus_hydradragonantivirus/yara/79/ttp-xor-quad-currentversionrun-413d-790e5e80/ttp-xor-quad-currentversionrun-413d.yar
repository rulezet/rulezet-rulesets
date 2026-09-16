rule TTP_XOR_QUAD_CurrentVersionRun_413d {
  strings:
    $key_413d = { 12 52 [2] 36 5c [2] 1d 70 [2] 33 52 [2] 27 49 [2] 28 53 [2] 36 4e [2] 34 4f [2] 2f 49 [2] 33 4e [2] 2f 61 }

  condition:
    any of them
}