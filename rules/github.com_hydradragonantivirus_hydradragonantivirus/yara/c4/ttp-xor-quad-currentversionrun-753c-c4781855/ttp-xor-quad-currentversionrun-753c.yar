rule TTP_XOR_QUAD_CurrentVersionRun_753c {
  strings:
    $key_753c = { 26 53 [2] 02 5d [2] 29 71 [2] 07 53 [2] 13 48 [2] 1c 52 [2] 02 4f [2] 00 4e [2] 1b 48 [2] 07 4f [2] 1b 60 }

  condition:
    any of them
}