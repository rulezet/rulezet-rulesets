rule TTP_XOR_QUAD_CurrentVersionRun_777d {
  strings:
    $key_777d = { 24 12 [2] 00 1c [2] 2b 30 [2] 05 12 [2] 11 09 [2] 1e 13 [2] 00 0e [2] 02 0f [2] 19 09 [2] 05 0e [2] 19 21 }

  condition:
    any of them
}