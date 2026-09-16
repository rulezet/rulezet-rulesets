rule TTP_XOR_QUAD_CurrentVersionRun_276d {
  strings:
    $key_276d = { 74 02 [2] 50 0c [2] 7b 20 [2] 55 02 [2] 41 19 [2] 4e 03 [2] 50 1e [2] 52 1f [2] 49 19 [2] 55 1e [2] 49 31 }

  condition:
    any of them
}