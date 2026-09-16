rule TTP_XOR_QUAD_CurrentVersionRun_194d {
  strings:
    $key_194d = { 4a 22 [2] 6e 2c [2] 45 00 [2] 6b 22 [2] 7f 39 [2] 70 23 [2] 6e 3e [2] 6c 3f [2] 77 39 [2] 6b 3e [2] 77 11 }

  condition:
    any of them
}