rule TTP_XOR_QUAD_CurrentVersionRun_722a {
  strings:
    $key_722a = { 21 45 [2] 05 4b [2] 2e 67 [2] 00 45 [2] 14 5e [2] 1b 44 [2] 05 59 [2] 07 58 [2] 1c 5e [2] 00 59 [2] 1c 76 }

  condition:
    any of them
}