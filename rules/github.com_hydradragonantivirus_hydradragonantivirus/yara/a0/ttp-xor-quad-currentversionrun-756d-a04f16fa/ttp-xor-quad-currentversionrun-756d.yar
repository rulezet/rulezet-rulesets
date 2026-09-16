rule TTP_XOR_QUAD_CurrentVersionRun_756d {
  strings:
    $key_756d = { 26 02 [2] 02 0c [2] 29 20 [2] 07 02 [2] 13 19 [2] 1c 03 [2] 02 1e [2] 00 1f [2] 1b 19 [2] 07 1e [2] 1b 31 }

  condition:
    any of them
}