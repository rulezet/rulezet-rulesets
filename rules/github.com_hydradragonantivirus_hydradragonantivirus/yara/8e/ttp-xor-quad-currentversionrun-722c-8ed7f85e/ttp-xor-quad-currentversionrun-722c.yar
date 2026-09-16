rule TTP_XOR_QUAD_CurrentVersionRun_722c {
  strings:
    $key_722c = { 21 43 [2] 05 4d [2] 2e 61 [2] 00 43 [2] 14 58 [2] 1b 42 [2] 05 5f [2] 07 5e [2] 1c 58 [2] 00 5f [2] 1c 70 }

  condition:
    any of them
}