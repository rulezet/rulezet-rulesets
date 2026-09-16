rule TTP_XOR_QUAD_CurrentVersionRun_457c {
  strings:
    $key_457c = { 16 13 [2] 32 1d [2] 19 31 [2] 37 13 [2] 23 08 [2] 2c 12 [2] 32 0f [2] 30 0e [2] 2b 08 [2] 37 0f [2] 2b 20 }

  condition:
    any of them
}