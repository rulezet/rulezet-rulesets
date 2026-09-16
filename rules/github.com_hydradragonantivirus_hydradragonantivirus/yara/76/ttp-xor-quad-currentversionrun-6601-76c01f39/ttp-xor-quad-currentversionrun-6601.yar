rule TTP_XOR_QUAD_CurrentVersionRun_6601 {
  strings:
    $key_6601 = { 35 6e [2] 11 60 [2] 3a 4c [2] 14 6e [2] 00 75 [2] 0f 6f [2] 11 72 [2] 13 73 [2] 08 75 [2] 14 72 [2] 08 5d }

  condition:
    any of them
}