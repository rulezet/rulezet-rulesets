rule TTP_XOR_QUAD_CurrentVersionRun_7b6c {
  strings:
    $key_7b6c = { 28 03 [2] 0c 0d [2] 27 21 [2] 09 03 [2] 1d 18 [2] 12 02 [2] 0c 1f [2] 0e 1e [2] 15 18 [2] 09 1f [2] 15 30 }

  condition:
    any of them
}