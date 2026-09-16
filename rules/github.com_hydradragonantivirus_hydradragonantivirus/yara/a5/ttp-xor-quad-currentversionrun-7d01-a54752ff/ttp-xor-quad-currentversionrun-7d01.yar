rule TTP_XOR_QUAD_CurrentVersionRun_7d01 {
  strings:
    $key_7d01 = { 2e 6e [2] 0a 60 [2] 21 4c [2] 0f 6e [2] 1b 75 [2] 14 6f [2] 0a 72 [2] 08 73 [2] 13 75 [2] 0f 72 [2] 13 5d }

  condition:
    any of them
}