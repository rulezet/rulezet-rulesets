rule TTP_XOR_QUAD_CurrentVersionRun_603d {
  strings:
    $key_603d = { 33 52 [2] 17 5c [2] 3c 70 [2] 12 52 [2] 06 49 [2] 09 53 [2] 17 4e [2] 15 4f [2] 0e 49 [2] 12 4e [2] 0e 61 }

  condition:
    any of them
}