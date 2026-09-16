rule TTP_XOR_QUAD_CurrentVersionRun_752a {
  strings:
    $key_752a = { 26 45 [2] 02 4b [2] 29 67 [2] 07 45 [2] 13 5e [2] 1c 44 [2] 02 59 [2] 00 58 [2] 1b 5e [2] 07 59 [2] 1b 76 }

  condition:
    any of them
}