rule TTP_XOR_QUAD_CurrentVersionRun_721c {
  strings:
    $key_721c = { 21 73 [2] 05 7d [2] 2e 51 [2] 00 73 [2] 14 68 [2] 1b 72 [2] 05 6f [2] 07 6e [2] 1c 68 [2] 00 6f [2] 1c 40 }

  condition:
    any of them
}