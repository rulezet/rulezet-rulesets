rule TTP_XOR_QUAD_CurrentVersionRun_721d {
  strings:
    $key_721d = { 21 72 [2] 05 7c [2] 2e 50 [2] 00 72 [2] 14 69 [2] 1b 73 [2] 05 6e [2] 07 6f [2] 1c 69 [2] 00 6e [2] 1c 41 }

  condition:
    any of them
}