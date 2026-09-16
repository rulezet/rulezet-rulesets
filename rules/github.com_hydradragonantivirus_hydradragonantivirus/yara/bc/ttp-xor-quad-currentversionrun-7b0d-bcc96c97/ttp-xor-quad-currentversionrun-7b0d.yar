rule TTP_XOR_QUAD_CurrentVersionRun_7b0d {
  strings:
    $key_7b0d = { 28 62 [2] 0c 6c [2] 27 40 [2] 09 62 [2] 1d 79 [2] 12 63 [2] 0c 7e [2] 0e 7f [2] 15 79 [2] 09 7e [2] 15 51 }

  condition:
    any of them
}