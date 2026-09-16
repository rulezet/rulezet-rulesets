rule TTP_XOR_QUAD_CurrentVersionRun_1d6c {
  strings:
    $key_1d6c = { 4e 03 [2] 6a 0d [2] 41 21 [2] 6f 03 [2] 7b 18 [2] 74 02 [2] 6a 1f [2] 68 1e [2] 73 18 [2] 6f 1f [2] 73 30 }

  condition:
    any of them
}