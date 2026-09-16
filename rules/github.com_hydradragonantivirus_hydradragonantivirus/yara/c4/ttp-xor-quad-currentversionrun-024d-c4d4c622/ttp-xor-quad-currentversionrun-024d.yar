rule TTP_XOR_QUAD_CurrentVersionRun_024d {
  strings:
    $key_024d = { 51 22 [2] 75 2c [2] 5e 00 [2] 70 22 [2] 64 39 [2] 6b 23 [2] 75 3e [2] 77 3f [2] 6c 39 [2] 70 3e [2] 6c 11 }

  condition:
    any of them
}