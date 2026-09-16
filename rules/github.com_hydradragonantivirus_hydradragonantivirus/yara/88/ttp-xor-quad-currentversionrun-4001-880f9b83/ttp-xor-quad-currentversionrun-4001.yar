rule TTP_XOR_QUAD_CurrentVersionRun_4001 {
  strings:
    $key_4001 = { 13 6e [2] 37 60 [2] 1c 4c [2] 32 6e [2] 26 75 [2] 29 6f [2] 37 72 [2] 35 73 [2] 2e 75 [2] 32 72 [2] 2e 5d }

  condition:
    any of them
}