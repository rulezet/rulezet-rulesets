rule TTP_XOR_QUAD_CurrentVersionRun_2e7d {
  strings:
    $key_2e7d = { 7d 12 [2] 59 1c [2] 72 30 [2] 5c 12 [2] 48 09 [2] 47 13 [2] 59 0e [2] 5b 0f [2] 40 09 [2] 5c 0e [2] 40 21 }

  condition:
    any of them
}