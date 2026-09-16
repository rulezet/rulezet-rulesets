rule TTP_XOR_QUAD_CurrentVersionRun_1d1c {
  strings:
    $key_1d1c = { 4e 73 [2] 6a 7d [2] 41 51 [2] 6f 73 [2] 7b 68 [2] 74 72 [2] 6a 6f [2] 68 6e [2] 73 68 [2] 6f 6f [2] 73 40 }

  condition:
    any of them
}