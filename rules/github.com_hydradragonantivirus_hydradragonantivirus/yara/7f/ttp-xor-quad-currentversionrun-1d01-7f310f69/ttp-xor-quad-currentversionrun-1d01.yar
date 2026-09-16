rule TTP_XOR_QUAD_CurrentVersionRun_1d01 {
  strings:
    $key_1d01 = { 4e 6e [2] 6a 60 [2] 41 4c [2] 6f 6e [2] 7b 75 [2] 74 6f [2] 6a 72 [2] 68 73 [2] 73 75 [2] 6f 72 [2] 73 5d }

  condition:
    any of them
}