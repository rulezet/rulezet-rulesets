rule TTP_XOR_QUAD_CurrentVersionRun_276c {
  strings:
    $key_276c = { 74 03 [2] 50 0d [2] 7b 21 [2] 55 03 [2] 41 18 [2] 4e 02 [2] 50 1f [2] 52 1e [2] 49 18 [2] 55 1f [2] 49 30 }

  condition:
    any of them
}