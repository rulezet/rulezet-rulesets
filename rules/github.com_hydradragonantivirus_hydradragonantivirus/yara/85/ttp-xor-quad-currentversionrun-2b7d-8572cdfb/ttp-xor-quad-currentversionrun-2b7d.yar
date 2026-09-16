rule TTP_XOR_QUAD_CurrentVersionRun_2b7d {
  strings:
    $key_2b7d = { 78 12 [2] 5c 1c [2] 77 30 [2] 59 12 [2] 4d 09 [2] 42 13 [2] 5c 0e [2] 5e 0f [2] 45 09 [2] 59 0e [2] 45 21 }

  condition:
    any of them
}