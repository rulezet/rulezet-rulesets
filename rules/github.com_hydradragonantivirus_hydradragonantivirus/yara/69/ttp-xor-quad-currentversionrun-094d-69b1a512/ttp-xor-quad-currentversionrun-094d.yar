rule TTP_XOR_QUAD_CurrentVersionRun_094d {
  strings:
    $key_094d = { 5a 22 [2] 7e 2c [2] 55 00 [2] 7b 22 [2] 6f 39 [2] 60 23 [2] 7e 3e [2] 7c 3f [2] 67 39 [2] 7b 3e [2] 67 11 }

  condition:
    any of them
}