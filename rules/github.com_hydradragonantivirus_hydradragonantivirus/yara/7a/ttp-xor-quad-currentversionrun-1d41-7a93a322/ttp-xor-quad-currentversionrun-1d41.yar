rule TTP_XOR_QUAD_CurrentVersionRun_1d41 {
  strings:
    $key_1d41 = { 4e 2e [2] 6a 20 [2] 41 0c [2] 6f 2e [2] 7b 35 [2] 74 2f [2] 6a 32 [2] 68 33 [2] 73 35 [2] 6f 32 [2] 73 1d }

  condition:
    any of them
}