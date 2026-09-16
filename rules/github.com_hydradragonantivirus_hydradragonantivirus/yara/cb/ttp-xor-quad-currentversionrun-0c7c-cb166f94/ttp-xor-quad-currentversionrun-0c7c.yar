rule TTP_XOR_QUAD_CurrentVersionRun_0c7c {
  strings:
    $key_0c7c = { 5f 13 [2] 7b 1d [2] 50 31 [2] 7e 13 [2] 6a 08 [2] 65 12 [2] 7b 0f [2] 79 0e [2] 62 08 [2] 7e 0f [2] 62 20 }

  condition:
    any of them
}