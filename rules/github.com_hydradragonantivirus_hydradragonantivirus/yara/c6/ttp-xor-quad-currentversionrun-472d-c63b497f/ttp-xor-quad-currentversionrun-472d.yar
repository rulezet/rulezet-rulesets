rule TTP_XOR_QUAD_CurrentVersionRun_472d {
  strings:
    $key_472d = { 14 42 [2] 30 4c [2] 1b 60 [2] 35 42 [2] 21 59 [2] 2e 43 [2] 30 5e [2] 32 5f [2] 29 59 [2] 35 5e [2] 29 71 }

  condition:
    any of them
}