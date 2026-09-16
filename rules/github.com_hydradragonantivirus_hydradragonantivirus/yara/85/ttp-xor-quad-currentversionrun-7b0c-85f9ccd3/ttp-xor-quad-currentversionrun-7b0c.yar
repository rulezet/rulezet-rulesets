rule TTP_XOR_QUAD_CurrentVersionRun_7b0c {
  strings:
    $key_7b0c = { 28 63 [2] 0c 6d [2] 27 41 [2] 09 63 [2] 1d 78 [2] 12 62 [2] 0c 7f [2] 0e 7e [2] 15 78 [2] 09 7f [2] 15 50 }

  condition:
    any of them
}