rule TTP_XOR_QUAD_CurrentVersionRun_4e2a {
  strings:
    $key_4e2a = { 1d 45 [2] 39 4b [2] 12 67 [2] 3c 45 [2] 28 5e [2] 27 44 [2] 39 59 [2] 3b 58 [2] 20 5e [2] 3c 59 [2] 20 76 }

  condition:
    any of them
}