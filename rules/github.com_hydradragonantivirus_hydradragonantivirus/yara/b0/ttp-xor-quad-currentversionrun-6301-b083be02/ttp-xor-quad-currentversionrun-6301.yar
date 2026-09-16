rule TTP_XOR_QUAD_CurrentVersionRun_6301 {
  strings:
    $key_6301 = { 30 6e [2] 14 60 [2] 3f 4c [2] 11 6e [2] 05 75 [2] 0a 6f [2] 14 72 [2] 16 73 [2] 0d 75 [2] 11 72 [2] 0d 5d }

  condition:
    any of them
}