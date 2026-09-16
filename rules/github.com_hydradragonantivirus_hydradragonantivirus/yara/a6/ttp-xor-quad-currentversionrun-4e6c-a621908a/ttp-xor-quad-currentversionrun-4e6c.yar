rule TTP_XOR_QUAD_CurrentVersionRun_4e6c {
  strings:
    $key_4e6c = { 1d 03 [2] 39 0d [2] 12 21 [2] 3c 03 [2] 28 18 [2] 27 02 [2] 39 1f [2] 3b 1e [2] 20 18 [2] 3c 1f [2] 20 30 }

  condition:
    any of them
}