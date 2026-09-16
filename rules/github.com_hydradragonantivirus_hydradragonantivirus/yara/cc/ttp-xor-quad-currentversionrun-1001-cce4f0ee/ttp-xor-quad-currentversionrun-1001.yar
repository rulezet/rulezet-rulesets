rule TTP_XOR_QUAD_CurrentVersionRun_1001 {
  strings:
    $key_1001 = { 43 6e [2] 67 60 [2] 4c 4c [2] 62 6e [2] 76 75 [2] 79 6f [2] 67 72 [2] 65 73 [2] 7e 75 [2] 62 72 [2] 7e 5d }

  condition:
    any of them
}