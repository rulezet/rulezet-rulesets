rule TTP_XOR_QUAD_CurrentVersionRun_256d {
  strings:
    $key_256d = { 76 02 [2] 52 0c [2] 79 20 [2] 57 02 [2] 43 19 [2] 4c 03 [2] 52 1e [2] 50 1f [2] 4b 19 [2] 57 1e [2] 4b 31 }

  condition:
    any of them
}