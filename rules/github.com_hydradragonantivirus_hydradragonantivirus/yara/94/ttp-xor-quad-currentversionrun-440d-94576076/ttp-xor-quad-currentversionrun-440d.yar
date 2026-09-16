rule TTP_XOR_QUAD_CurrentVersionRun_440d {
  strings:
    $key_440d = { 17 62 [2] 33 6c [2] 18 40 [2] 36 62 [2] 22 79 [2] 2d 63 [2] 33 7e [2] 31 7f [2] 2a 79 [2] 36 7e [2] 2a 51 }

  condition:
    any of them
}