rule TTP_XOR_QUAD_CurrentVersionRun_722d {
  strings:
    $key_722d = { 21 42 [2] 05 4c [2] 2e 60 [2] 00 42 [2] 14 59 [2] 1b 43 [2] 05 5e [2] 07 5f [2] 1c 59 [2] 00 5e [2] 1c 71 }

  condition:
    any of them
}