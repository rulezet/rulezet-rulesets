rule TTP_XOR_QUAD_CurrentVersionRun_294d {
  strings:
    $key_294d = { 7a 22 [2] 5e 2c [2] 75 00 [2] 5b 22 [2] 4f 39 [2] 40 23 [2] 5e 3e [2] 5c 3f [2] 47 39 [2] 5b 3e [2] 47 11 }

  condition:
    any of them
}