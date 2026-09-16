rule TTP_XOR_QUAD_CurrentVersionRun_752c {
  strings:
    $key_752c = { 26 43 [2] 02 4d [2] 29 61 [2] 07 43 [2] 13 58 [2] 1c 42 [2] 02 5f [2] 00 5e [2] 1b 58 [2] 07 5f [2] 1b 70 }

  condition:
    any of them
}