rule TTP_XOR_QUAD_CurrentVersionRun_703a {
  strings:
    $key_703a = { 23 55 [2] 07 5b [2] 2c 77 [2] 02 55 [2] 16 4e [2] 19 54 [2] 07 49 [2] 05 48 [2] 1e 4e [2] 02 49 [2] 1e 66 }

  condition:
    any of them
}