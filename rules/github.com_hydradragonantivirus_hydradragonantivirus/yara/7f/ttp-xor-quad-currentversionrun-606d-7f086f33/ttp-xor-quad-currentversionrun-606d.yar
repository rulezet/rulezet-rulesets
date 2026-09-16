rule TTP_XOR_QUAD_CurrentVersionRun_606d {
  strings:
    $key_606d = { 33 02 [2] 17 0c [2] 3c 20 [2] 12 02 [2] 06 19 [2] 09 03 [2] 17 1e [2] 15 1f [2] 0e 19 [2] 12 1e [2] 0e 31 }

  condition:
    any of them
}