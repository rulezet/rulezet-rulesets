rule TTP_XOR_QUAD_CurrentVersionRun_f241 {
  strings:
    $key_f241 = { a1 2e [2] 85 20 [2] ae 0c [2] 80 2e [2] 94 35 [2] 9b 2f [2] 85 32 [2] 87 33 [2] 9c 35 [2] 80 32 [2] 9c 1d }

  condition:
    any of them
}