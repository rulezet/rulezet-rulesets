rule TTP_XOR_QUAD_CurrentVersionRun_1e6c {
  strings:
    $key_1e6c = { 4d 03 [2] 69 0d [2] 42 21 [2] 6c 03 [2] 78 18 [2] 77 02 [2] 69 1f [2] 6b 1e [2] 70 18 [2] 6c 1f [2] 70 30 }

  condition:
    any of them
}