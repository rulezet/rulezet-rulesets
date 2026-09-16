rule TTP_XOR_QUAD_CurrentVersionRun_723a {
  strings:
    $key_723a = { 21 55 [2] 05 5b [2] 2e 77 [2] 00 55 [2] 14 4e [2] 1b 54 [2] 05 49 [2] 07 48 [2] 1c 4e [2] 00 49 [2] 1c 66 }

  condition:
    any of them
}