rule TTP_XOR_QUAD_CurrentVersionRun_3c1d {
  strings:
    $key_3c1d = { 6f 72 [2] 4b 7c [2] 60 50 [2] 4e 72 [2] 5a 69 [2] 55 73 [2] 4b 6e [2] 49 6f [2] 52 69 [2] 4e 6e [2] 52 41 }

  condition:
    any of them
}