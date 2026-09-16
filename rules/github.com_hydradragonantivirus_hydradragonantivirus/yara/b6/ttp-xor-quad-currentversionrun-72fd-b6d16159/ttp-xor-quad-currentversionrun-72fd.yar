rule TTP_XOR_QUAD_CurrentVersionRun_72fd {
  strings:
    $key_72fd = { 21 92 [2] 05 9c [2] 2e b0 [2] 00 92 [2] 14 89 [2] 1b 93 [2] 05 8e [2] 07 8f [2] 1c 89 [2] 00 8e [2] 1c a1 }

  condition:
    any of them
}