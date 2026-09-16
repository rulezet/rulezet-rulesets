rule TTP_XOR_QUAD_CurrentVersionRun_104d {
  strings:
    $key_104d = { 43 22 [2] 67 2c [2] 4c 00 [2] 62 22 [2] 76 39 [2] 79 23 [2] 67 3e [2] 65 3f [2] 7e 39 [2] 62 3e [2] 7e 11 }

  condition:
    any of them
}