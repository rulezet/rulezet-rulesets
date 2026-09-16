rule TTP_XOR_QUAD_CurrentVersionRun_0c6a {
  strings:
    $key_0c6a = { 5f 05 [2] 7b 0b [2] 50 27 [2] 7e 05 [2] 6a 1e [2] 65 04 [2] 7b 19 [2] 79 18 [2] 62 1e [2] 7e 19 [2] 62 36 }

  condition:
    any of them
}