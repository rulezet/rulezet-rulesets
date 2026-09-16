rule TTP_XOR_QUAD_CurrentVersionRun_410d {
  strings:
    $key_410d = { 12 62 [2] 36 6c [2] 1d 40 [2] 33 62 [2] 27 79 [2] 28 63 [2] 36 7e [2] 34 7f [2] 2f 79 [2] 33 7e [2] 2f 51 }

  condition:
    any of them
}