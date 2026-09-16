rule TTP_XOR_QUAD_CurrentVersionRun_4c6c {
  strings:
    $key_4c6c = { 1f 03 [2] 3b 0d [2] 10 21 [2] 3e 03 [2] 2a 18 [2] 25 02 [2] 3b 1f [2] 39 1e [2] 22 18 [2] 3e 1f [2] 22 30 }

  condition:
    any of them
}