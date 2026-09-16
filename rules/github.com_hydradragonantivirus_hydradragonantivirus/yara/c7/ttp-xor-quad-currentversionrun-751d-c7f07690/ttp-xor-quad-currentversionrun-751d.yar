rule TTP_XOR_QUAD_CurrentVersionRun_751d {
  strings:
    $key_751d = { 26 72 [2] 02 7c [2] 29 50 [2] 07 72 [2] 13 69 [2] 1c 73 [2] 02 6e [2] 00 6f [2] 1b 69 [2] 07 6e [2] 1b 41 }

  condition:
    any of them
}