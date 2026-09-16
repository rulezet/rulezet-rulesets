rule TTP_XOR_QUAD_CurrentVersionRun_2b4d {
  strings:
    $key_2b4d = { 78 22 [2] 5c 2c [2] 77 00 [2] 59 22 [2] 4d 39 [2] 42 23 [2] 5c 3e [2] 5e 3f [2] 45 39 [2] 59 3e [2] 45 11 }

  condition:
    any of them
}