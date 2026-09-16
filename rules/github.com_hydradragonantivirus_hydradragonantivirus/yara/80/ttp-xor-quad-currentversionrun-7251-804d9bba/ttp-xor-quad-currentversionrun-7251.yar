rule TTP_XOR_QUAD_CurrentVersionRun_7251 {
  strings:
    $key_7251 = { 21 3e [2] 05 30 [2] 2e 1c [2] 00 3e [2] 14 25 [2] 1b 3f [2] 05 22 [2] 07 23 [2] 1c 25 [2] 00 22 [2] 1c 0d }

  condition:
    any of them
}