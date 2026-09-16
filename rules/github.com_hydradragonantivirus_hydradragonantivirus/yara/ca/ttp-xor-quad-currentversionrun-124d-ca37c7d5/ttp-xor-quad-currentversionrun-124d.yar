rule TTP_XOR_QUAD_CurrentVersionRun_124d {
  strings:
    $key_124d = { 41 22 [2] 65 2c [2] 4e 00 [2] 60 22 [2] 74 39 [2] 7b 23 [2] 65 3e [2] 67 3f [2] 7c 39 [2] 60 3e [2] 7c 11 }

  condition:
    any of them
}