rule TTP_XOR_QUAD_CurrentVersionRun_7501 {
  strings:
    $key_7501 = { 26 6e [2] 02 60 [2] 29 4c [2] 07 6e [2] 13 75 [2] 1c 6f [2] 02 72 [2] 00 73 [2] 1b 75 [2] 07 72 [2] 1b 5d }

  condition:
    any of them
}