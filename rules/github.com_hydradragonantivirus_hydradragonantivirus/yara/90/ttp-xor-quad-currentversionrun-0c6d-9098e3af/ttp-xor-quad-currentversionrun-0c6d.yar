rule TTP_XOR_QUAD_CurrentVersionRun_0c6d {
  strings:
    $key_0c6d = { 5f 02 [2] 7b 0c [2] 50 20 [2] 7e 02 [2] 6a 19 [2] 65 03 [2] 7b 1e [2] 79 1f [2] 62 19 [2] 7e 1e [2] 62 31 }

  condition:
    any of them
}