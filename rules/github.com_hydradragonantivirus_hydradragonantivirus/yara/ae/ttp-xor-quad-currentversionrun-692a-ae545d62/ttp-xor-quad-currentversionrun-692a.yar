rule TTP_XOR_QUAD_CurrentVersionRun_692a {
  strings:
    $key_692a = { 3a 45 [2] 1e 4b [2] 35 67 [2] 1b 45 [2] 0f 5e [2] 00 44 [2] 1e 59 [2] 1c 58 [2] 07 5e [2] 1b 59 [2] 07 76 }

  condition:
    any of them
}