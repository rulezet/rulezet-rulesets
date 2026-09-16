rule TTP_XOR_QUAD_CurrentVersionRun_413a {
  strings:
    $key_413a = { 12 55 [2] 36 5b [2] 1d 77 [2] 33 55 [2] 27 4e [2] 28 54 [2] 36 49 [2] 34 48 [2] 2f 4e [2] 33 49 [2] 2f 66 }

  condition:
    any of them
}