rule TTP_XOR_QUAD_CurrentVersionRun_6c1d {
  strings:
    $key_6c1d = { 3f 72 [2] 1b 7c [2] 30 50 [2] 1e 72 [2] 0a 69 [2] 05 73 [2] 1b 6e [2] 19 6f [2] 02 69 [2] 1e 6e [2] 02 41 }

  condition:
    any of them
}