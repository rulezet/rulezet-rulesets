rule TTP_XOR_QUAD_CurrentVersionRun_204d {
  strings:
    $key_204d = { 73 22 [2] 57 2c [2] 7c 00 [2] 52 22 [2] 46 39 [2] 49 23 [2] 57 3e [2] 55 3f [2] 4e 39 [2] 52 3e [2] 4e 11 }

  condition:
    any of them
}