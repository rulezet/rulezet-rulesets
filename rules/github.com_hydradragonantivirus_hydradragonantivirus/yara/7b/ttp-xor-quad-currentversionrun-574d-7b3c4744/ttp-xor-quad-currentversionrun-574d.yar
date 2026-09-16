rule TTP_XOR_QUAD_CurrentVersionRun_574d {
  strings:
    $key_574d = { 04 22 [2] 20 2c [2] 0b 00 [2] 25 22 [2] 31 39 [2] 3e 23 [2] 20 3e [2] 22 3f [2] 39 39 [2] 25 3e [2] 39 11 }

  condition:
    any of them
}