rule TTP_XOR_QUAD_CurrentVersionRun_324d {
  strings:
    $key_324d = { 61 22 [2] 45 2c [2] 6e 00 [2] 40 22 [2] 54 39 [2] 5b 23 [2] 45 3e [2] 47 3f [2] 5c 39 [2] 40 3e [2] 5c 11 }

  condition:
    any of them
}