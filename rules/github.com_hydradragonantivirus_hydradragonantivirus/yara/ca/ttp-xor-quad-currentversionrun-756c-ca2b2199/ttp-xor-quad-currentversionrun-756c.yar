rule TTP_XOR_QUAD_CurrentVersionRun_756c {
  strings:
    $key_756c = { 26 03 [2] 02 0d [2] 29 21 [2] 07 03 [2] 13 18 [2] 1c 02 [2] 02 1f [2] 00 1e [2] 1b 18 [2] 07 1f [2] 1b 30 }

  condition:
    any of them
}